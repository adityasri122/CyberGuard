import win32evtlog
import win32evtlogutil
import win32con
from datetime import datetime, timedelta
import xml.etree.ElementTree as ET

def analyze_security_logs():
    """
    Queries the Windows 'Security' Event Log for failed logon attempts
    using pywin32.
    """
    print("Log Analyzer: Starting scan of 'Security' logs...")
    
    server = 'localhost'
    log_type = 'Security'
    
    seven_days_ago = datetime.now() - timedelta(days=7)
    query_time_str = seven_days_ago.strftime('%Y-%m-%dT%H:%M:%S.000Z')
    
    query = f"*[System[(EventID=4625) and TimeCreated[@SystemTime > '{query_time_str}']]]"

    failed_logons = []
    
    try:
        # --- THIS IS THE FIX ---
        # We are using EvtQueryChannelPath to query the live log channel,
        # not EvtQueryFilePath.
        hand = win32evtlog.EvtQuery(
            log_type, 
            win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection, 
            query
        )
        # --- END OF FIX ---
        
    except Exception as e:
        if "Access is denied" in str(e):
            print("LOG ANALYZER ERROR: Access Denied. Please run as Administrator.")
            return "Access Denied"
        print(f"Log query failed: {e}")
        return None

    while True:
        try:
            events = win32evtlog.EvtNext(hand, 10)
            if not events:
                break
                
            for event in events:
                xml_data = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
                
                try:
                    xml = ET.fromstring(xml_data)
                    ns = { 'e': 'http://schemas.microsoft.com/win/2004/08/events/event' }
                    
                    username = "Unknown"
                    for data_elem in xml.findall('.//e:EventData/e:Data', ns):
                        if data_elem.get('Name') == 'TargetUserName':
                            username = data_elem.text
                            break
                    
                    time_created = xml.find('.//e:System/e:TimeCreated', ns).get('SystemTime')
                    
                    failed_logons.append({
                        "time": time_created.split('.')[0], 
                        "username": username,
                        "event_id": 4625
                    })
                except Exception as e:
                    print(f"Error parsing single event: {e}")
                    
        except win32evtlog.Win32apiError:
            break 

    print(f"Log Analyzer: Found {len(failed_logons)} failed logon attempts.")
    return failed_logons

# --- You can run this file directly to test it ---
if __name__ == "__main__":
    results = analyze_security_logs()
    
    if isinstance(results, list):
        print(f"\nFound {len(results)} failed logons:")
        for logon in results[:10]:
            print(f"  - [{logon['time']}] Failed logon for user: {logon['username']}")
    else:
        print(f"Test failed: {results}")