"""
Tests for ScanIcs scanner.
Run with: python -m pytest src/python/strelka/tests/test_scan_ics.py -v
"""
from pathlib import Path
from unittest import mock

import pytest

from strelka.scanners.scan_ics import ScanIcs
from strelka import strelka


class TestScanIcs:
    """Tests for ScanIcs scanner."""

    @pytest.fixture
    def fixture_path(self):
        return Path(__file__).parent / "fixtures/test_phishing.ics"

    @pytest.fixture
    def ics_data(self, fixture_path):
        with open(fixture_path, "rb") as f:
            return f.read()

    @pytest.fixture
    def scanner(self):
        """Create a scanner instance with mocked dependencies."""
        backend_cfg = {"limits": {"scanner": 30}}
        mock_coordinator = mock.MagicMock()
        scanner = ScanIcs(backend_cfg, mock_coordinator)
        scanner.upload_to_coordinator = mock.MagicMock()
        return scanner

    def run_scan(self, scanner, ics_data):
        """Run the scanner and return the event."""
        file = strelka.File(name="test.ics")
        files, event = scanner.scan_wrapper(
            data=ics_data,
            file=file,
            options={},
            expire_at=0
        )
        return event.get("ics", {})

    def test_calendar_metadata(self, scanner, ics_data):
        """Test that calendar metadata is correctly extracted."""
        event = self.run_scan(scanner, ics_data)

        assert len(event.get("calendars", [])) == 1
        cal = event["calendars"][0]

        assert cal.get("prodid") == "Microsoft Exchange Server 2010"
        assert cal.get("version") == "2.0"
        assert cal.get("method") == "REQUEST"

    def test_component_counts(self, scanner, ics_data):
        """Test that component counts are accurate."""
        event = self.run_scan(scanner, ics_data)

        totals = event.get("total", {})
        assert totals.get("events") == 1
        assert totals.get("timezones") == 1
        assert totals.get("attendees") == 2
        assert totals.get("organizers") == 1

    def test_vevent_metadata(self, scanner, ics_data):
        """Test that VEVENT metadata is correctly extracted."""
        event = self.run_scan(scanner, ics_data)

        # Find the VEVENT component
        vevent = None
        for comp in event["calendars"][0]["components"]:
            if comp.get("type") == "VEVENT":
                vevent = comp
                break

        assert vevent is not None
        assert vevent.get("summary") == "Fw: Reminder - 2026 Annual Work Report "
        assert vevent.get("uid") == "test-uid-12345-phishing-ics"
        assert vevent.get("location") == "Conference Room"
        assert vevent.get("status") == "CONFIRMED"

    def test_attendee_extraction(self, scanner, ics_data):
        """Test that attendees are correctly extracted."""
        event = self.run_scan(scanner, ics_data)

        vevent = None
        for comp in event["calendars"][0]["components"]:
            if comp.get("type") == "VEVENT":
                vevent = comp
                break

        attendees = vevent.get("attendees", [])
        assert len(attendees) == 2

        # Check first attendee
        helpdesk = next((a for a in attendees if "helpdesk" in a.get("email", "")), None)
        assert helpdesk is not None
        assert helpdesk.get("email") == "helpdesk@example.com"
        assert helpdesk.get("name") == "ACME Corp IT Help Desk"
        assert helpdesk.get("role") == "REQ-PARTICIPANT"
        assert helpdesk.get("rsvp") == "TRUE"

    def test_organizer_extraction(self, scanner, ics_data):
        """Test that organizer is correctly extracted."""
        event = self.run_scan(scanner, ics_data)

        vevent = None
        for comp in event["calendars"][0]["components"]:
            if comp.get("type") == "VEVENT":
                vevent = comp
                break

        organizers = vevent.get("organizers", [])
        assert len(organizers) == 1
        assert organizers[0].get("name") == "ACME Corp Share-File"

    def test_url_extraction_from_description(self, scanner, ics_data):
        """Test that URLs are extracted from DESCRIPTION field - critical for phishing detection."""
        event = self.run_scan(scanner, ics_data)

        vevent = None
        for comp in event["calendars"][0]["components"]:
            if comp.get("type") == "VEVENT":
                vevent = comp
                break

        urls = vevent.get("urls", [])
        
        # Should find 3 URLs embedded in the description
        assert len(urls) == 3
        
        # Check for the malicious phishing URL (sanitized test version)
        phishing_url = next((u for u in urls if "malicious-phishing-site" in u), None)
        assert phishing_url is not None
        assert "lambda-url.us-east-1.on.aws" in phishing_url
        
        # Check for legitimate URLs also extracted
        facebook_url = next((u for u in urls if "facebook.com" in u), None)
        assert facebook_url is not None
        
        linkedin_url = next((u for u in urls if "linkedin.com" in u), None)
        assert linkedin_url is not None

    def test_url_total_count(self, scanner, ics_data):
        """Test that total URL count is tracked."""
        event = self.run_scan(scanner, ics_data)

        totals = event.get("total", {})
        assert totals.get("urls") == 3

    def test_description_contains_phishing_indicators(self, scanner, ics_data):
        """Test that description text is available for analysis."""
        event = self.run_scan(scanner, ics_data)

        vevent = None
        for comp in event["calendars"][0]["components"]:
            if comp.get("type") == "VEVENT":
                vevent = comp
                break

        description = vevent.get("description", "")
        
        # Check for phishing indicators in the description
        assert "Is this phishing?" in description
        assert "Work_Order_Authorization_Form" in description
        assert "Job expires on" in description
        assert "attacker@malicious-domain.org" in description

    def test_datetime_extraction(self, scanner, ics_data):
        """Test that date/time fields are correctly extracted."""
        event = self.run_scan(scanner, ics_data)

        vevent = None
        for comp in event["calendars"][0]["components"]:
            if comp.get("type") == "VEVENT":
                vevent = comp
                break

        # Check that datetime fields are present and formatted
        assert vevent.get("dtstart") is not None
        assert vevent.get("dtend") is not None
        assert "2026-01-14" in vevent.get("dtstart", "")

    def test_no_parse_errors(self, scanner, ics_data):
        """Test that the ICS file parses without errors."""
        event = self.run_scan(scanner, ics_data)

        assert "parse_error" not in event
        assert "ics_parse_error" not in event.get("flags", [])

    def test_timezone_component(self, scanner, ics_data):
        """Test that timezone components are extracted."""
        event = self.run_scan(scanner, ics_data)

        vtimezone = None
        for comp in event["calendars"][0]["components"]:
            if comp.get("type") == "VTIMEZONE":
                vtimezone = comp
                break

        assert vtimezone is not None
        assert vtimezone.get("tzid") == "Greenwich Standard Time"
