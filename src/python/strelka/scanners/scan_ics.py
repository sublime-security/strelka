from icalendar import Calendar, vBinary, vCalAddress, vUri

from strelka import strelka


class ScanIcs(strelka.Scanner):
    """Extracts metadata and embedded files from iCalendar (ICS) files.
    
    This scanner processes RFC5545 compliant iCalendar files commonly used for
    calendar invitations, meeting requests, and event sharing. It provides both
    structured metadata extraction and security analysis capabilities.
    
    Key Features:
    - Calendar metadata extraction (PRODID, VERSION, METHOD, etc.)
    - Component analysis (VEVENT, VTODO, VJOURNAL, VTIMEZONE, VALARM)
    - Attendee and organizer information parsing
    - Attachment extraction with multiple format support:
      * vBinary objects (traditional base64 embedded files)
      * Data URIs (data:mime/type;base64,content)
      * Base64 binary attachments (ENCODING=BASE64 parameter)
      * Regular URIs (stored as metadata)
    - Human-readable duration formatting (e.g., "-15m" instead of "-1 day, 23:45:00")

    Dependencies:
        - icalendar library (tested with 6.3.1)
    """

    def scan(self, data, file, options, expire_at):
        """Main scanning function that processes ICS file data.
        
        Args:
            data: Raw ICS file bytes
            file: Strelka File object
            options: Scanner configuration options
            expire_at: File expiration timestamp
        """
        # Calendar bomb protection: Limits prevent resource exhaustion while 
        # preserving attack detection through total counts and flags
        self.limits = {
            'max_components': options.get('max_components', 1000),
            'max_attendees_per_component': options.get('max_attendees_per_component', 100),
            'max_organizers_per_component': options.get('max_organizers_per_component', 10),
            'max_attachments_per_component': options.get('max_attachments_per_component', 50)
        }
        
        # Track totals for both analysis and bomb detection
        # Total counts continue even when storage limits are hit
        self.event['total'] = {
            'components': 0,      # All calendar components (VEVENT, VTODO, etc.)
            'events': 0,          # VEVENT components
            'todos': 0,           # VTODO components  
            'journals': 0,        # VJOURNAL components
            'timezones': 0,       # VTIMEZONE components
            'alarms': 0,          # VALARM components
            'attachments': 0,     # All ATTACH properties
            'extracted_files': 0, # Successfully extracted attachment files
            'attendees': 0,       # All ATTENDEE properties across components
            'organizers': 0,      # All ORGANIZER properties across components
            'urls': 0             # All URL properties (potential phishing/C2 links)
        }
        
        try:
            # Parse the ICS data using icalendar
            calendar = Calendar.from_ical(data, multiple=True)
            
            # Handle both single calendar and multiple calendar cases
            if not isinstance(calendar, list):
                calendar = [calendar]
            
            self.event['calendars'] = []
            
            for cal_idx, cal in enumerate(calendar):
                cal_data = self._extract_calendar_metadata(cal)
                
                # Process all components in the calendar
                cal_data['components'] = []
                for component in cal.walk():
                    self.event['total']['components'] += 1
                    
                    # Limit stored components to prevent memory exhaustion
                    if len(cal_data['components']) < self.limits['max_components']:
                        comp_data = self._process_component(component, expire_at)
                        if comp_data:
                            cal_data['components'].append(comp_data)
                    else:
                        # Still count but don't store - indicates potential bomb
                        self.flags.append(f'component_limit_exceeded_{self.limits["max_components"]}')
                
                self.event['calendars'].append(cal_data)
            
        except Exception as e:
            self.flags.append('ics_parse_error')
            self.event['parse_error'] = str(e)

    def _extract_calendar_metadata(self, calendar):
        """Extract top-level calendar metadata."""
        metadata = {}
        
        # Extract key calendar fields for convenience
        calendar_convenience_fields = ['PRODID', 'VERSION', 'METHOD', 'CALSCALE', 'NAME', 'DESCRIPTION']
        for field_name in calendar_convenience_fields:
            if field_name in calendar:
                convenience_field = field_name.lower()
                metadata[convenience_field] = str(calendar[field_name])
        
        return metadata

    def _process_component(self, component, expire_at):
        """Process individual calendar components (VEVENT, VTODO, etc.)."""
        comp_name = component.name
        if not comp_name or comp_name == 'VCALENDAR':
            return None
            
        comp_data = {
            'type': comp_name,
            'attendees': [],
            'organizers': [],
            'attachments': [],
            'urls': []
        }
        
        # Track component types
        if comp_name == 'VEVENT':
            self.event['total']['events'] += 1
        elif comp_name == 'VTODO':
            self.event['total']['todos'] += 1
        elif comp_name == 'VJOURNAL':
            self.event['total']['journals'] += 1
        elif comp_name == 'VTIMEZONE':
            self.event['total']['timezones'] += 1
        elif comp_name == 'VALARM':
            self.event['total']['alarms'] += 1
        
        # Process all properties in the component
        for prop, value in component.items():
            if prop == 'ATTENDEE':
                # Handle both single attendee and list of attendees
                attendees = value if isinstance(value, list) else [value]
                for attendee in attendees:
                    self.event['total']['attendees'] += 1
                    
                    # Limit stored attendees per component
                    if len(comp_data['attendees']) < self.limits['max_attendees_per_component']:
                        attendee_data = self._extract_attendee_data(attendee)
                        comp_data['attendees'].append(attendee_data)
                    else:
                        self.flags.append(f'attendee_limit_exceeded_per_component_{self.limits["max_attendees_per_component"]}')
                
            elif prop == 'ORGANIZER':
                self.event['total']['organizers'] += 1
                
                # Limit stored organizers per component
                if len(comp_data['organizers']) < self.limits['max_organizers_per_component']:
                    organizer_data = self._extract_organizer_data(value)
                    comp_data['organizers'].append(organizer_data)
                else:
                    self.flags.append(f'organizer_limit_exceeded_per_component_{self.limits["max_organizers_per_component"]}')
                
            elif prop == 'ATTACH':
                # Handle both single attachment and list of attachments
                attachments = value if isinstance(value, list) else [value]
                for attachment in attachments:
                    self.event['total']['attachments'] += 1
                    
                    # Limit stored attachments per component  
                    if len(comp_data['attachments']) < self.limits['max_attachments_per_component']:
                        attachment_data = self._process_attachment(attachment, expire_at)
                        comp_data['attachments'].append(attachment_data)
                    else:
                        self.flags.append(f'attachment_limit_exceeded_per_component_{self.limits["max_attachments_per_component"]}')
            
            elif prop == 'URL':
                self.event['total']['urls'] += 1
                comp_data['urls'].append(str(value))
                
            # Skip storing individual properties - only keep convenience fields
        
        # Extract key fields to parent level based on component type
        self._extract_component_convenience_fields(comp_data, component)
        
        return comp_data

    def _extract_component_convenience_fields(self, comp_data, component):
        """Extract key fields to parent level for easier access."""
        comp_type = comp_data['type']
        
        # Common fields for most components
        common_fields = ['SUMMARY', 'DESCRIPTION', 'UID']
        
        # Component-specific fields
        type_specific_fields = {
            'VEVENT': ['DTSTART', 'DTEND', 'DURATION', 'LOCATION', 'STATUS'],
            'VTODO': ['DTSTART', 'DUE', 'DURATION', 'PRIORITY', 'STATUS', 'PERCENT-COMPLETE'],
            'VJOURNAL': ['DTSTART', 'DURATION'],
            'VTIMEZONE': ['TZID'],
            'VALARM': ['TRIGGER', 'ACTION', 'REPEAT', 'DURATION'],
        }
        
        # Get fields to extract for this component type
        fields_to_extract = common_fields + type_specific_fields.get(comp_type, [])
        
        # Extract the fields from the component
        for field_name in fields_to_extract:
            if field_name in component:
                # Convert field name to lowercase for the convenience field
                convenience_field = field_name.lower().replace('-', '_')
                
                # Special handling for date/time/duration fields
                if field_name in ['DTSTART', 'DTEND', 'DUE', 'DURATION', 'DTSTAMP', 'CREATED', 'LAST-MODIFIED', 'TRIGGER']:
                    comp_data[convenience_field] = self._extract_datetime_value(component[field_name])
                else:
                    comp_data[convenience_field] = str(component[field_name])

    def _extract_datetime_value(self, dt_value):
        """Extract clean datetime/date/duration values from icalendar objects."""
        # Check if it has the .dt property (vDDDTypes, vDuration, etc.)
        if hasattr(dt_value, 'dt'):
            dt_obj = dt_value.dt
            # Check if it's a timedelta (duration like TRIGGER:-PT15M)
            if hasattr(dt_obj, 'total_seconds'):
                return self._format_duration(dt_obj)
            # Convert date/datetime objects to ISO strings for JSON serialization
            elif hasattr(dt_obj, 'isoformat'):
                return dt_obj.isoformat()
            else:
                return str(dt_obj)
        # Check if it has the .td property (vDuration -> timedelta)
        elif hasattr(dt_value, 'td'):
            return self._format_duration(dt_value.td)  # Convert timedelta to readable format
        # Fallback to string serialization
        else:
            return str(dt_value)

    def _format_duration(self, td):
        """Format timedelta objects into human-readable strings.
        
        Converts confusing Python timedelta representations like "-1 day, 23:45:00"
        into clear, analyst-friendly formats like "-15m".
        
        Common use cases:
        - TRIGGER:-PT15M becomes "-15m" (15 minutes before event)
        - DURATION:PT1H30M becomes "1h30m" (1 hour 30 minute duration)
        
        Args:
            td: datetime.timedelta object
            
        Returns:
            str: Human-readable duration (e.g., "-15m", "2h", "1d", "30s")
        """
        total_seconds = int(td.total_seconds())
        
        if total_seconds == 0:
            return "0"
        
        # Handle negative durations (common in TRIGGER properties)
        sign = "-" if total_seconds < 0 else ""
        total_seconds = abs(total_seconds)
        
        # Break down into time units
        days = total_seconds // 86400
        hours = (total_seconds % 86400) // 3600
        minutes = (total_seconds % 3600) // 60
        seconds = total_seconds % 60
        
        # Build readable format prioritizing larger units
        parts = []
        if days:
            parts.append(f"{days}d")
        if hours:
            parts.append(f"{hours}h")
        if minutes:
            parts.append(f"{minutes}m")
        if seconds and not (days or hours or minutes):  # Only show seconds if it's the only unit
            parts.append(f"{seconds}s")
        
        return sign + "".join(parts) if parts else f"{sign}{total_seconds}s"

    def _extract_attendee_data(self, attendee):
        """Extract attendee information with parsed details."""
        attendee_data = {
            'email': None,
            'name': None,
            'role': None,
            'partstat': None,
            'rsvp': None
        }
        
        # Handle vCalAddress objects using built-in properties
        if isinstance(attendee, vCalAddress):
            attendee_data['email'] = attendee.email
            attendee_data['name'] = attendee.name
            attendee_data['role'] = attendee.params.get('ROLE') if hasattr(attendee, 'params') else None
            attendee_data['partstat'] = attendee.params.get('PARTSTAT') if hasattr(attendee, 'params') else None
            attendee_data['rsvp'] = attendee.params.get('RSVP') if hasattr(attendee, 'params') else None
            
            # Create standard "Display Name <email@address>" format
            if attendee_data['name'] and attendee_data['email']:
                attendee_data['display_name'] = f"{attendee_data['name']} <{attendee_data['email']}>"
            elif attendee_data['email']:
                attendee_data['display_name'] = attendee_data['email']
            elif attendee_data['name']:
                attendee_data['display_name'] = attendee_data['name']
        
        return attendee_data

    def _extract_organizer_data(self, organizer):
        """Extract organizer information with parsed details."""
        organizer_data = {
            'email': None,
            'name': None
        }
        
        # Handle vCalAddress objects using built-in properties
        if isinstance(organizer, vCalAddress):
            organizer_data['email'] = organizer.email
            organizer_data['name'] = organizer.name
            
            # Create standard "Display Name <email@address>" format
            if organizer_data['name'] and organizer_data['email']:
                organizer_data['display_name'] = f"{organizer_data['name']} <{organizer_data['email']}>"
            elif organizer_data['email']:
                organizer_data['display_name'] = organizer_data['email']
            elif organizer_data['name']:
                organizer_data['display_name'] = organizer_data['name']
        
        return organizer_data

    def _process_attachment(self, attachment, expire_at):
        """Process ATTACH properties - the primary attack vector in malicious ICS files.
        
        Handles multiple attachment formats found in the wild:
        1. vBinary objects - Traditional icalendar embedded files
        2. Data URIs - Self-contained base64 data (data:mime/type;base64,content)
        3. Base64 binary - ENCODING=BASE64 parameter format
        4. Regular URIs - External file references
        
        Security note: Attachments are the main way malware is distributed via
        calendar files. This method extracts embedded content for analysis while
        flagging suspicious patterns.
        
        Args:
            attachment: icalendar attachment object (vBinary, vUri, or string)
            expire_at: File expiration timestamp
            
        Returns:
            dict: Attachment metadata with type, size, filename, extraction status
        """
        attachment_data = {
            'type': 'other'
        }
        
        
        # Classify attachment type and extract if possible
        if isinstance(attachment, vBinary):
            # Traditional icalendar binary attachment
            attachment_data['type'] = 'binary'
            self._extract_binary_attachment(attachment, attachment_data, expire_at)
            
        elif isinstance(attachment, vUri) or self._is_uri(str(attachment)):
            uri = str(attachment)
            
            # Data URI with embedded base64 content (treat as binary)
            if uri.startswith('data:') and ';base64,' in uri:
                attachment_data['type'] = 'binary'
                # Don't store massive base64 data - just extract the file
                self._extract_data_uri(attachment, attachment_data, expire_at)
            # Base64 binary with ENCODING parameter (common in Outlook/Exchange)
            elif self._get_attachment_param(attachment, 'ENCODING') == 'BASE64':
                attachment_data['type'] = 'base64_binary'
                # Skip storing massive base64 string - just extract the file
                self._extract_base64_binary_attachment(attachment, attachment_data, expire_at)
            else:
                # Regular URI reference to external file
                attachment_data['type'] = 'uri'
                attachment_data['uri'] = uri  # Store for IOC analysis
            
        return attachment_data
    
    def _get_attachment_param(self, attachment, param_name):
        """Get parameter value from attachment object."""
        if hasattr(attachment, 'params') and param_name in attachment.params:
            return attachment.params[param_name]
        return None
    
    
    def _extract_binary_attachment(self, attachment, attachment_data, expire_at):
        """Extract binary attachment data."""
        try:
            binary_data = attachment.obj
            mime_type = self._get_attachment_param(attachment, 'FMTTYPE')
            filename = self._get_attachment_param(attachment, 'X-FILENAME') or self._get_attachment_param(attachment, 'FILENAME')
            
            if not filename:
                filename = f'ics_attachment_{self.event["total"]["attachments"]}'
            
            extract_file = self._create_extracted_file(binary_data, filename, mime_type, expire_at)
            
            # Update attachment metadata
            attachment_data['extracted'] = True
            attachment_data['size'] = str(len(binary_data))
            if mime_type:
                attachment_data['mime_type'] = mime_type
            attachment_data['filename'] = filename
            
        except Exception as e:
            self.flags.append('attachment_decode_error')
            attachment_data['decode_error'] = str(e)
    
    def _extract_data_uri(self, attachment, attachment_data, expire_at):
        """Extract file from data URI with base64 content."""
        try:
            import base64
            
            data_uri = str(attachment)
            if ';base64,' not in data_uri:
                return
                
            header, encoded_data = data_uri.split(';base64,', 1)
            mime_type = header.replace('data:', '')
            decoded_data = base64.b64decode(encoded_data)
            
            filename = (self._get_attachment_param(attachment, 'X-FILENAME') or 
                       self._get_attachment_param(attachment, 'FILENAME') or
                       self._generate_filename(mime_type))
            
            extract_file = self._create_extracted_file(decoded_data, filename, mime_type, expire_at)
            
            # Update attachment metadata
            attachment_data['extracted'] = True
            attachment_data['size'] = str(len(decoded_data))
            if mime_type:
                attachment_data['mime_type'] = mime_type
            attachment_data['filename'] = filename
            
        except Exception as e:
            self.flags.append('data_uri_decode_error')
            attachment_data['decode_error'] = str(e)
    
    def _extract_base64_binary_attachment(self, attachment, attachment_data, expire_at):
        """Extract base64-encoded binary attachment (ENCODING=BASE64)."""
        try:
            import base64
            
            # Decode base64 data
            base64_data = str(attachment)
            decoded_data = base64.b64decode(base64_data)
            
            # Get filename and mime type from parameters
            filename = self._get_attachment_param(attachment, 'X-FILENAME') or self._get_attachment_param(attachment, 'FILENAME')
            mime_type = self._get_attachment_param(attachment, 'FMTTYPE')
            
            if not filename:
                filename = f'ics_attachment_{self.event["total"]["attachments"]}'
            
            extract_file = self._create_extracted_file(decoded_data, filename, mime_type, expire_at)
            
            # Update attachment metadata
            attachment_data['extracted'] = True
            attachment_data['size'] = str(len(decoded_data))
            if mime_type:
                attachment_data['mime_type'] = mime_type
            attachment_data['filename'] = filename
            
        except Exception as e:
            self.flags.append('base64_binary_decode_error')
            attachment_data['decode_error'] = str(e)
    
    
    def _generate_filename(self, mime_type):
        """Generate filename from MIME type."""
        ext_map = {
            'application/pdf': '.pdf',
            'text/plain': '.txt', 
            'application/json': '.json',
            'image/png': '.png',
            'image/jpeg': '.jpg'
        }
        ext = ext_map.get(mime_type, '.bin')
        return f'ics_data_uri_{self.event["total"]["attachments"]}{ext}'
    
    def _create_extracted_file(self, data, filename, mime_type, expire_at):
        """Create and upload extracted file to Strelka coordinator."""
        extract_file = strelka.File(name=filename, source=self.name)
        
        if mime_type:
            extract_file.add_flavors({'external': [mime_type]})
        
        for c in strelka.chunk_string(data):
            self.upload_to_coordinator(extract_file.pointer, c, expire_at)
        
        self.files.append(extract_file)
        self.event['total']['extracted_files'] += 1
        
        return extract_file

    def _is_uri(self, value):
        """Check if a string value appears to be a URI."""
        uri_schemes = ['http', 'https', 'ftp', 'file', 'mailto', 'cid', 'data']
        value_lower = value.lower()
        return any(value_lower.startswith(f'{scheme}:') for scheme in uri_schemes)

