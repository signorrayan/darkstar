import unittest
import sys
import os
import pandas as pd
import xml.etree.ElementTree as ET
from unittest.mock import patch, MagicMock, mock_open

# Add the parent directory to the path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from modules.openvas import openvas


class TestOpenVAS(unittest.TestCase):
    """Test the OpenVAS scanner functionality."""

    def test_initialization(self):
        """Test initializing the OpenVAS scanner."""
        scanner = openvas("192.168.1.1", "test_org")
        
        self.assertEqual(scanner.ips, "192.168.1.1")
        self.assertEqual(scanner.org_name, "test_org")
        self.assertEqual(scanner.username, os.getenv('OPENVAS_USER'))
        self.assertEqual(scanner.password, os.getenv('OPENVAS_PASSWORD'))
        self.assertEqual(scanner.vulnerabilities, [])
        self.assertEqual(scanner.queue_reportIDs, [])
        self.assertEqual(scanner.queue_scan_names, [])
        self.assertEqual(scanner.queue_report_location, [])

    def test_split_cidr(self):
        """Test splitting CIDR ranges."""
        scanner = openvas("192.168.1.0/24", "test_org")
        
        # Test with a small subnet that doesn't need splitting
        small_subnet = scanner.split_cidr("192.168.1.0/24")
        self.assertEqual(len(small_subnet), 1)
        self.assertEqual(small_subnet[0], "192.168.1.0/24")
        
        # Test with a large subnet that needs splitting
        large_subnet = scanner.split_cidr("10.0.0.0/8")
        self.assertTrue(len(large_subnet) > 1)
        self.assertTrue(all(subnet.startswith("10.") for subnet in large_subnet))

    @patch('modules.openvas.requests.post')
    def test_get_report(self, mock_post):
        """Test retrieving a report from OpenVAS."""
        # Mock the API response
        mock_response = MagicMock()
        mock_response.json.return_value = {'message': '<report>Test report content</report>'}
        mock_post.return_value = mock_response
        
        scanner = openvas("192.168.1.1", "test_org")
        scanner.command_prefix = "mock_prefix"
        scanner.formatID = "mock_format_id"
        
        # Mock file opening
        with patch('builtins.open', mock_open()) as mock_file:
            scanner.get_report("report123", "/tmp/report.xml")
            
            # Verify API call and file write
            mock_post.assert_called_once()
            mock_file.assert_called_once_with("/tmp/report.xml", "w")
            mock_file().write.assert_called_once_with('<report>Test report content</report>')

    @patch('modules.openvas.requests.post')
    def test_check_if_finished_done(self, mock_post):
        """Test checking if a scan is finished and is done."""
        # Create a more realistic XML response that matches what OpenVAS API returns
        # The scan status is nested under a <report> tag
        xml_response = '''
        <get_reports_response status="200" status_text="OK">
          <report id="report123">
            <scan_run_status>Done</scan_run_status>
          </report>
        </get_reports_response>
        '''
        
        mock_response = MagicMock()
        mock_response.json.return_value = {'message': xml_response}
        mock_post.return_value = mock_response
        
        scanner = openvas("192.168.1.1", "test_org")
        scanner.command_prefix = "mock_prefix"
        scanner.formatID = "mock_format_id"
        
        result = scanner.check_if_finished("report123")
        self.assertTrue(result)
    
    @patch('modules.openvas.requests.post')
    def test_check_if_finished_running(self, mock_post):
        """Test checking if a scan is running with progress."""
        # Create XML response indicating scan is running
        xml_response = '<report><scan_run_status>Running</scan_run_status><progress>50</progress></report>'
        
        mock_response = MagicMock()
        mock_response.json.return_value = {'message': xml_response}
        mock_post.return_value = mock_response
        
        scanner = openvas("192.168.1.1", "test_org")
        scanner.command_prefix = "mock_prefix"
        scanner.formatID = "mock_format_id"
        
        result = scanner.check_if_finished("report123")
        self.assertFalse(result)

    @patch('modules.openvas.ET.parse')
    @patch('modules.openvas.insert_vulnerability_to_database')
    @patch('modules.vulns.Vulnerability')  # Mock the Vulnerability class to prevent CVE enrichment
    def test_process_findings(self, mock_vuln_class, mock_insert, mock_parse):
        """Test processing vulnerability findings from an XML report."""
        # Setup mock vulnerability instance
        mock_vuln_instance = MagicMock()
        mock_vuln_class.return_value = mock_vuln_instance
        
        # Create a mock XML structure
        mock_root = MagicMock()
        mock_result = MagicMock()
        mock_nvt = MagicMock()
        mock_qod = MagicMock()
        
        # Set up the attributes for the finding
        mock_result.find.side_effect = lambda x: {
            'name': MagicMock(text="Test Vulnerability"),
            'nvt': mock_nvt,
            'port': MagicMock(text="443/tcp"),
            'threat': MagicMock(text="High"),
            'severity': MagicMock(text="7.5"),
            'description': MagicMock(text="Test description"),
            'host': MagicMock(text="192.168.1.1"),
            'qod': mock_qod
        }[x]
        
        mock_nvt.find.return_value = MagicMock(text="CVE-2021-12345")
        mock_qod.find.return_value = MagicMock(text="95")
        
        # Set up the root to return our mock result
        mock_root.findall.return_value = [mock_result]
        mock_parse.return_value.getroot.return_value = mock_root
        
        # Create the scanner and process the findings
        scanner = openvas("192.168.1.1", "test_org")
        scanner.process_findings("/tmp/report.xml")
        
        # Verify vulnerability was created and inserted
        self.assertEqual(len(scanner.vulnerabilities), 1)
        mock_insert.assert_called_once()

    @patch('modules.openvas.threading.Thread')
    def test_run_with_valid_targets(self, mock_thread):
        """Test running OpenVAS scan with valid targets."""
        # Create a scanner with IP addresses
        targets = pd.Series(["192.168.1.1", "192.168.1.2"])
        scanner = openvas(targets, "test_org")
        
        # Mock the scan creation methods
        scanner.create_target = MagicMock()
        scanner.create_task = MagicMock()
        scanner.run_task = MagicMock()
        
        # Run the scan
        with patch('time.sleep'):  # Don't actually sleep in tests
            scanner.run()
            
        # Verify methods were called for each target
        self.assertEqual(scanner.create_target.call_count, 2)
        self.assertEqual(scanner.create_task.call_count, 2)
        self.assertEqual(scanner.run_task.call_count, 2)
        
        # Verify monitoring thread was started
        mock_thread.assert_called_once_with(target=scanner.wait_for_scan)
        mock_thread.return_value.start.assert_called_once()

    def test_run_with_empty_targets(self):
        """Test running OpenVAS scan with empty targets."""
        # Create a scanner with empty series
        empty_series = pd.Series([])
        scanner = openvas(empty_series, "test_org")
        
        # Mock the scan creation methods
        scanner.create_target = MagicMock()
        scanner.create_task = MagicMock()
        scanner.run_task = MagicMock()
        
        # Run the scan
        scanner.run()
        
        # Verify no methods were called due to empty targets
        scanner.create_target.assert_not_called()
        scanner.create_task.assert_not_called()
        scanner.run_task.assert_not_called()

    def test_run_with_nan_targets(self):
        """Test running OpenVAS scan with NaN targets."""
        # Create a scanner with NaN values
        nan_series = pd.Series([float('nan')])
        scanner = openvas(nan_series, "test_org")
        
        # Mock the scan creation methods
        scanner.create_target = MagicMock()
        scanner.create_task = MagicMock()
        scanner.run_task = MagicMock()
        
        # Run the scan
        scanner.run()
        
        # Verify no methods were called due to NaN targets
        scanner.create_target.assert_not_called()
        scanner.create_task.assert_not_called()
        scanner.run_task.assert_not_called()

    @patch('modules.openvas.logging.error')
    @patch('modules.openvas.requests.post')
    def test_api_error_handling(self, mock_post, mock_log):
        """Test handling of API errors in OpenVAS scanner."""
        # Set up mock to simulate API error response
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.json.side_effect = ValueError("Invalid JSON")
        mock_post.return_value = mock_response
        
        scanner = openvas("192.168.1.1", "test_org")
        scanner.command_prefix = "mock_prefix"
        scanner.formatID = "mock_format_id"
        
        # Test error handling in check_if_finished
        result = scanner.check_if_finished("report123")
        self.assertFalse(result)  # Should return False on error
        mock_log.assert_called()  # Should log the error
        
        mock_log.reset_mock()  # Reset the mock for the next test
        
        # Test error handling in get_report
        with patch('builtins.open', mock_open()) as mock_file:
            scanner.get_report("report123", "/tmp/report.xml")
            mock_log.assert_called()  # Should log the error
            # Verify file wasn't written to
            mock_file().write.assert_not_called()


if __name__ == '__main__':
    unittest.main()