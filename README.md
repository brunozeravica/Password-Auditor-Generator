# Password Auditor & Generator
#### Description:
This project is a command-line security utility written in Python that evaluates password strength and generates secure passwords. Standard password strength meters on websites usually rely on basic regular expressions, such as checking for the presence of a single uppercase letter, number or symbol. These checks, however, fail to account for mathematical complexity, use of common language, or commonly used passwords which may have already been exposed in a data breach, which hackers utilize with dictionary attacks. This project was built to address those shortcomings. 

The program operates in two modes: "--audit", which evaluates a user provided password on a scale from 0 to 100%, and "--generate", which randomly generates a password based on the required security score.

**Audit**\
When a password is entered, it's validated within the `get_password` function which checks for length, characters (using the `validate_character_set` function), and whether or not the password appears in the https://haveibeenpwned.com/ database, using the *pwnedpasswords.check* API call.

If the password is valid it passes through 3 additional checks which are combined to get the final score:

1. **Entropy**\
Using the standard formula

$$E = L \cdot log_2(R)$$

where L is the length of the password and R is the number of possible characters used, the passwords entropy is calculated. This value is essentially a measure of how many random guesses it would take to correctly guess this password. The maximum value for a 32 character password, which is the maximum supported length, is just over 209 bits of entropy. This fact is used to normalize the calculated entropy to a range of 0 to 100 and then returned.

2. **Pattern matching**\
Using the `scan_patterns` function the password is compared against a curated list of 10,000 common passwords. If the password is a substring of any of the entries, or if any of the entries are a substring within the password, the `match_count` variable is incremented by 1, and it is then returned at the end of the function.. This takes care of the most common cases, such as "password", as well as common english words.

3. **Uniqueness**\
In order to approximate the diversity of characters in a password, we calculate the ratio of unique characters to the total length of the password. This value is then passed through a shifted and scaled hyperbolic tangent function:

$$f(x) = \frac{\tanh(k \cdot (x - x_0)) + 1}{2}$$

where:

+ $$x$$ is the uniqueness ratio
+ $$x_0 = 0.25$$ is an experimentally derived constant 
+ $$k = 5$$ is an experimentally derived constant

This way passwords with extremely low uniqueness ratios are completely squashed to 0% (eg. "aabbaaabba"), but a password isn't required to have every single character be completely unique in order to get a high score. 

**Score calculation**\
​
Lastly, the `calculate_score` function calls all 3 of these functions, and calculates the score: 

$$score = (entropy - (5 \cdot pattern)) \cdot uniqueness$$ 

This formula, like the parameters of the uniqueness *tanh* function were derived via trial and error, until the output of the password auditor followed the *KeePassXC* password auditor score sufficiently well. If the password is extremely common, it may be highly penalized by the `scan_patterns` function, for this reason this function doesn't return the calculated score, but rather the max value between 0 and the calculated score, so as to limit the minimum output to 0.

**Generate**\
The user is prompted for a target password score, which is limited to a minimum of 25% for security. Based on the selected score, a set of characters and length is selected, with scores above or equal to 55 utilizing the entire character set (upper and lowercase letters, numbers, ascii punctuation), while the length of the password is directly proportional to the target score, with a minimum of 3 generated characters. The password is generated continually character by character using the secrets library for cryptographically secure randomness and when the required length is reached, the password is checked against the programs own password audit system. If the password meets the desired password score within 10%, the loop is broken and the password is returned, otherwise the password is scrapped and regenerated from scratch.


**Files**\
The project contains several files, based on the requirements of the project:
+ *project.py* - The main application file. Contains the `main()` function, the CLI logic, the audit and generate passwords functionalities.
+ *test_project.py* - The unit test. Uses pytest and monkeypatch to simulate user inputs and verify that the scoring logic is consistent and all returned values are of the correct type.
+ *passwords.txt* - A localized database of 10,000 common passwords.
+ *requirements.txt* - A list of the required external libraries


This was the final project for Harvard's CS50P course.
