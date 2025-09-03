from icalendar import Calendar, vBinary, vCalAddress, vUri

from strelka import strelka


class ScanIcs(strelka.Scanner):
    """Extracts metadata and embedded files from iCalendar (ICS) files.
    
    This scanner processes RFC5545 compliant iCalendar files, extracting:
    - Calendar metadata (PRODID, VERSION, METHOD, etc.)
    - Event details (VEVENT)  
    - Todo items (VTODO)
    - Journal entries (VJOURNAL)
    - Timezone information (VTIMEZONE)
    - Attendee information with parsed details
    - Embedded attachments (vBinary) as extractable files
    - URI attachments for analysis
    
    Dependencies:
        - icalendar library
    """

    def scan(self, data, file, options, expire_at):
        self.event['total'] = {
            'components': 0,
            'events': 0, 
            'todos': 0,
            'journals': 0,
            'timezones': 0,
            'alarms': 0,
            'attachments': 0,
            'extracted_files': 0,
            'attendees': 0,
            'organizers': 0
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
                    comp_data = self._process_component(component, expire_at)
                    if comp_data:
                        cal_data['components'].append(comp_data)
                        self.event['total']['components'] += 1
                
                self.event['calendars'].append(cal_data)
            
        except Exception as e:
            self.flags.append('ics_parse_error')
            self.event['parse_error'] = str(e)

    def _extract_calendar_metadata(self, calendar):
        """Extract top-level calendar metadata."""
        metadata = {
            'properties': []
        }
        
        # Extract all calendar-level properties as array of dicts
        for prop, value in calendar.items():
            prop_data = {
                'name': prop,
                'value': self._serialize_property_value(value)
            }
            metadata['properties'].append(prop_data)
        
        return metadata

    def _process_component(self, component, expire_at):
        """Process individual calendar components (VEVENT, VTODO, etc.)."""
        comp_name = component.name
        if not comp_name or comp_name == 'VCALENDAR':
            return None
            
        comp_data = {
            'type': comp_name,
            'properties': [],
            'attendees': [],
            'organizers': [],
            'attachments': []
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
                attendee_data = self._extract_attendee_data(value)
                comp_data['attendees'].append(attendee_data)
                self.event['total']['attendees'] += 1
                
            elif prop == 'ORGANIZER':
                organizer_data = self._extract_organizer_data(value)
                comp_data['organizers'].append(organizer_data)
                self.event['total']['organizers'] += 1
                
            elif prop == 'ATTACH':
                attachment_data = self._process_attachment(value, expire_at)
                comp_data['attachments'].append(attachment_data)
                self.event['total']['attachments'] += 1
                
            else:
                # Store all other properties
                prop_data = {
                    'name': prop,
                    'value': self._serialize_property_value(value)
                }
                comp_data['properties'].append(prop_data)
        
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
                    comp_data[convenience_field] = self._serialize_property_value(component[field_name])

    def _extract_datetime_value(self, dt_value):
        """Extract clean datetime/date/duration values from icalendar objects."""
        # Check if it has the .dt property (vDDDTypes, vDuration, etc.)
        if hasattr(dt_value, 'dt'):
            return dt_value.dt
        # Fallback to string serialization
        else:
            return self._serialize_property_value(dt_value)

    def _extract_attendee_data(self, attendee):
        """Extract attendee information with parsed details."""
        attendee_data = {
            'params': [],
            'email': None,
            'name': None,
            'role': None,
            'partstat': None,
            'rsvp': None,
            'raw': str(attendee)
        }
        
        # Handle vCalAddress objects using built-in properties
        if isinstance(attendee, vCalAddress):
            # Use the built-in properties directly
            attendee_data['email'] = attendee.email
            attendee_data['name'] = attendee.name
            attendee_data['role'] = attendee.params.get('ROLE') if hasattr(attendee, 'params') else None
            attendee_data['partstat'] = attendee.params.get('PARTSTAT') if hasattr(attendee, 'params') else None
            attendee_data['rsvp'] = attendee.params.get('RSVP') if hasattr(attendee, 'params') else None
            
            # Extract all parameters as array of dicts for forensics
            if hasattr(attendee, 'params'):
                for param_name, param_value in attendee.params.items():
                    param_data = {
                        'name': param_name,
                        'value': param_value
                    }
                    attendee_data['params'].append(param_data)
        
        else:
            # Fallback for non-vCalAddress types
            attendee_str = str(attendee)
            if attendee_str.startswith('mailto:'):
                attendee_data['email'] = attendee_str[7:]  # Remove 'mailto:' prefix
            else:
                attendee_data['email'] = attendee_str
            
        return attendee_data

    def _extract_organizer_data(self, organizer):
        """Extract organizer information with parsed details."""
        organizer_data = {
            'params': [],
            'email': None,
            'name': None,
            'raw': str(organizer)
        }
        
        # Handle vCalAddress objects using built-in properties
        if isinstance(organizer, vCalAddress):
            # Use the built-in properties directly
            organizer_data['email'] = organizer.email
            organizer_data['name'] = organizer.name
            
            # Extract all parameters as array of dicts for forensics
            if hasattr(organizer, 'params'):
                for param_name, param_value in organizer.params.items():
                    param_data = {
                        'name': param_name,
                        'value': param_value
                    }
                    organizer_data['params'].append(param_data)
        
        else:
            # Fallback for non-vCalAddress types
            organizer_str = str(organizer)
            if organizer_str.startswith('mailto:'):
                organizer_data['email'] = organizer_str[7:]  # Remove 'mailto:' prefix
            else:
                organizer_data['email'] = organizer_str
                
        return organizer_data

    def _process_attachment(self, attachment, expire_at):
        """Process ATTACH properties, handling both vBinary and vUri."""
        attachment_data = {
            'type': None,
            'params': [],
            'raw': str(attachment)
        }
        
        # Extract parameters as array of dicts if available
        if hasattr(attachment, 'params'):
            for param_name, param_value in attachment.params.items():
                param_data = {
                    'name': param_name,
                    'value': param_value
                }
                attachment_data['params'].append(param_data)
        
        # Handle vBinary attachments (base64 encoded files)
        if isinstance(attachment, vBinary):
            attachment_data['type'] = 'binary'
            
            try:
                # Use the .obj property to get the raw binary data
                decoded_data = attachment.obj
                
                # Determine filename from parameters
                filename = None
                mime_type = None
                for param in attachment_data['params']:
                    param_name = param.get('name', '')
                    param_value = param.get('value', '')
                    if param_name in ['X-FILENAME', 'FILENAME']:
                        filename = param_value
                    elif param_name == 'FMTTYPE':
                        mime_type = param_value
                
                if not filename:
                    filename = f'ics_attachment_{self.event["total"]["attachments"]}'
                
                # Create extracted file
                extract_file = strelka.File(
                    name=filename,
                    source=self.name,
                )
                
                # Add MIME type flavor if available
                if mime_type:
                    extract_file.add_flavors({'external': [mime_type]})
                    attachment_data['mime_type'] = mime_type
                
                # Upload the decoded data to be processed
                for c in strelka.chunk_string(decoded_data):
                    self.upload_to_coordinator(
                        extract_file.pointer,
                        c,
                        expire_at,
                    )
                
                self.files.append(extract_file)
                self.event['total']['extracted_files'] += 1
                
                attachment_data['extracted'] = True
                attachment_data['size'] = str(len(decoded_data))
                attachment_data['filename'] = filename
                
            except Exception as e:
                self.flags.append('attachment_decode_error')
                attachment_data['decode_error'] = str(e)
        
        # Handle vUri attachments (URI references)
        elif isinstance(attachment, vUri):
            attachment_data['type'] = 'uri'
            # vUri inherits from str, so str() gives us the clean URI
            attachment_data['uri'] = str(attachment)
            
        else:
            # Handle other attachment types - check if it looks like a URI
            attachment_str = str(attachment)
            if self._is_uri(attachment_str):
                attachment_data['type'] = 'uri'
                attachment_data['uri'] = attachment_str
            else:
                attachment_data['type'] = 'other'
            
        return attachment_data

    def _is_uri(self, value):
        """Check if a string value appears to be a URI."""
        uri_schemes = ['http', 'https', 'ftp', 'file', 'mailto', 'cid', 'data']
        value_lower = value.lower()
        return any(value_lower.startswith(f'{scheme}:') for scheme in uri_schemes)

    def _serialize_property_value(self, value):
        """Serialize property values for JSON storage."""
        if hasattr(value, 'to_ical'):
            ical_value = value.to_ical()
            if isinstance(ical_value, bytes):
                return ical_value.decode('utf-8', errors='ignore')
            else:
                return str(ical_value)
        else:
            return str(value)