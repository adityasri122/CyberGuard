def calculate_overall_score(password_list, network_list, log_list):
    """
    Calculates a unified security score from all module results
    using an ADDITIVE model.
    
    Score is out of 100 points:
    - Password Score: 35 points
    - Breach Score:   25 points
    - URL Safety Score: 15 points
    - Network Score:   15 points
    - Log Score:       10 points
    """
    total_score = 0
    issues = []

    # === 1. Password Score (Max 35 points) ===
    password_score = 0
    if password_list:
        total_passwords = len(password_list)
        strong_count = 0
        weak_count = 0
        for p in password_list:
            verdict = p.get('strength_verdict', 'Empty')
            if verdict in ["Strong", "Very Strong"]: strong_count += 1
            elif verdict in ["Weak", "Very Weak"]: weak_count += 1
        strong_ratio = strong_count / total_passwords
        password_score += strong_ratio * 35  # Earn up to 35 points
        weak_ratio = weak_count / total_passwords
        password_score -= weak_ratio * 20 # Penalty
        if weak_count > 0: issues.append(f"{weak_count} Weak password(s)")

    # === 2. Breach Score (Max 25 points) ===
    breach_score = 0
    if password_list:
        emails_to_check = set(p.get('username') for p in password_list if '@' in p.get('username', ''))
        total_emails = len(emails_to_check)
        breached_emails = 0
        if total_emails > 0:
            for p in password_list:
                if p.get('username') in emails_to_check:
                    if p.get('breach_count', 0) > 0:
                        breached_emails += 1
                        emails_to_check.remove(p.get('username'))
            unbreached_ratio = 1.0 - (breached_emails / total_emails)
            breach_score = unbreached_ratio * 25 # Earn up to 25 points
            if breached_emails > 0: issues.append(f"{breached_emails} email(s) in data breaches")
        else:
            breach_score = 25 

    # === 3. URL Safety Score (Max 15 points) ===
    url_score = 0
    if password_list:
        total_urls = len(password_list)
        safe_count = 0
        for p in password_list:
            verdict = p.get('url_verdict', '✔️ Safe')
            if verdict == '✔️ Safe': safe_count += 1
            elif verdict == '⚠️ Insecure (HTTP)': issues.append("Insecure HTTP login")
            elif verdict.startswith("❌ Suspicious"): issues.append("Suspicious URL")
        safe_ratio = safe_count / total_urls
        url_score = safe_ratio * 15

    # === 4. Network Score (Max 15 points) ===
    network_score = 15
    if network_list:
        for dev in network_list:
            ports = dev.get('ports', '')
            if '23/tcp' in ports: network_score -= 10; issues.append(f"Insecure Telnet open on {dev['ip']}")
            if '21/tcp' in ports: network_score -= 5; issues.append(f"Insecure FTP open on {dev['ip']}")
    network_score = max(0, network_score)

    # === 5. Log Score (Max 10 points) ===
    log_score = 10 # Start with full points
    if isinstance(log_list, list):
        failed_count = len(log_list)
        if failed_count > 50:
            log_score = 0 # Heavy penalty
            issues.append(f"High ({failed_count}+) failed logons")
        elif failed_count > 10:
            log_score = 5 # Medium penalty
            issues.append(f"{failed_count} failed logons")
        # 0-10 failed logons is normal, no penalty

    # --- Final Score Calculation ---
    total_score = password_score + breach_score + url_score + network_score + log_score
    total_score = int(max(0, min(100, total_score)))
        
    # --- Get Verdict ---
    if total_score >= 90: verdict = "Excellent (A)"
    elif total_score >= 70: verdict = "Good (B)"
    elif total_score >= 50: verdict = "Fair (C)"
    elif total_score >= 30: verdict = "Poor (D)"
    else: verdict = "Critical (F)"
        
    top_issues = list(set(issues))[:3]
    if not top_issues and total_score < 100:
        top_issues = ["Multiple minor issues found"]
    elif not top_issues and total_score == 100:
        top_issues = ["No major issues found!"]

    return {
        "score": total_score,
        "verdict": verdict,
        "top_issues": top_issues
    }