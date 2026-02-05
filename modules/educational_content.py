# This file stores all the text for the Educational Mode tab.

TOPICS = {
    "What is a Strong Password?": """
    <h2>What Makes a Password Strong?</h2>
    <p>A strong password is not just complex, it's <b>long</b> and <b>unpredictable</b>.</p>
    <ul>
        <li><b>Length is Key:</b> A 12-character password, even if simple, is 
        exponentially harder to crack than an 8-character complex one. Aim for 16+ characters.</li>
        
        <li><b>Complexity:</b> Use a mix of uppercase letters (A-Z), lowercase letters (a-z),
        numbers (0-9), and symbols (!@#$).</li>
        
        <li><b>Unpredictability:</b> This is the most important part.
            <ul>
                <li><b>Avoid</b> common words ('password', 'dragon'), keyboard patterns ('qwerty'),
                and sequences ('12345').</li>
                <li><b>Avoid</b> personal information. Your name, birthday, or pet's name are the
                first things an attacker will try.</li>
            </ul>
        </li>
    </ul>
    
    <h3>The Best Strategy: Passphrases</h3>
    <p>Instead of trying to remember <b>'P@$$w0rd!123'</b>, remember a passphrase like
    <b>'Correct-Horse-Battery-Staple'</b>. It's 28 characters long, easy for you to
    remember, and almost impossible for a computer to guess.</p>
    
    <h3>Your Best Defense: Password Managers</h3>
    <p>The single best thing you can do for your security is to use a <b>Password Manager</b>
    (like Bitwarden, 1Password, or KeePass). They create and store unique, 20+ character
    random passwords for every single site you use. You only have to remember one
    master password.</p>
    """,
    
    "How Password Cracking Works": """
    <h2>How Does the Cracking Simulation Work?</h2>
    <p>This app uses <b>Hashcat</b>, a real tool used by security professionals and hackers.
    It works by making millions of guesses per second.</p>
    
    <h3>1. Dictionary Attack (The 'rockyou.txt' list)</h3>
    <p>We first test your password against a list of over 14 million known breached passwords
    (rockyou.txt). If your password is on this list, it can be cracked in <b>less than a second</b>,
    no matter how complex it looks.</p>
    
    <h3>2. Hybrid Attack (The 'words_alpha.txt' + rules)</h3>
    <p>This is much smarter. It takes a base dictionary (like 'password') and applies rules
    to it, just like a human would.</p>
    <ul>
        <li>password -> <b>P</b>assword</li>
        <li>password -> password<b>123</b></li>
        <li>password -> <b>P</b>assword<b>!</b></li>
        <li>password -> <b>P@$$w0rd!</b></li>
    </ul>
    <p>Our simulation runs this hybrid attack. If it finds your password, it means
    your password is just a common word with simple changes, making it very weak.</p>
    """,
    
    "What is Phishing?": """
    <h2>What is Phishing?</h2>
    <p>Phishing is a cyberattack where an attacker sends a fraudulent message designed
    to trick you into revealing sensitive information.</p>
    
    <h3>Red Flags (How to Spot a Phish)</h3>
    <ul>
        <li><b>Suspicious URL:</b> This is the #1 sign. Always check the link before you click.
        A fake site might look like '<b>microsft.com</b>' (missing an 'o') or
        '<b>login.google.com.security-update.xyz</b>'. The *real* domain is the part
        just before the '.com' or '.xyz'. In the second example, the real domain is
        'security-update.xyz', not 'google.com'.</li>
        
        <li><b>Sense of Urgency:</b> The email screams "Immediate Action Required!" or
        "Your account will be suspended!" This is designed to make you panic and not think clearly.</li>
        
        <li><b>Insecure (HTTP):</b> Your browser will show a "Not Secure" warning. <b>NEVER</b>
        enter a password on a site that starts with <b>http://</b>. Always look for
        <b>https://</b>.</li>
        
        <li><b>Spelling & Grammar Mistakes:</b> Professional companies rarely make
        obvious spelling errors in their official emails.</li>
    </ul>
    """,
    
    "What is OSINT (Breach Scan)?": """
    <h2>What is OSINT (Data Breach Scan)?</h2>
    <p><b>OSINT</b> stands for Open Source Intelligence. It means finding information
    from publicly available sources. The "Breach Count" column in your audit uses
    the 'Have I Been Pwned' (HIBP) database.</p>
    
    <h3>What does a "breach" mean?</h3>
    <p>If your email is in a breach, it means a website you signed up for (e.g., 'MyFitnessPal' in 2018)
    was hacked, and the hackers stole the entire user database—including your email and,
    most likely, your password hash.</p>
    
    <h3>Why does this matter?</h3>
    <p>Attackers will take that stolen password and try it on other major sites
    (like your email, your bank, your social media). This is called <b>Credential Stuffing</b>.</p>
    <p>This is why it is <b>CRITICAL</b> to use a <b>unique password for every single site.</b>
    If one site gets breached, the attackers can't get into any of your other accounts.</p>
    """
}