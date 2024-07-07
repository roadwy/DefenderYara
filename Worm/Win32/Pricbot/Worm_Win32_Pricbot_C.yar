
rule Worm_Win32_Pricbot_C{
	meta:
		description = "Worm:Win32/Pricbot.C,SIGNATURE_TYPE_PEHSTR,10 00 10 00 0d 00 00 "
		
	strings :
		$a_01_0 = {63 6f 70 79 74 6f 00 73 70 72 65 61 64 55 53 42 00 } //10
		$a_01_1 = {70 69 72 63 62 6f 74 } //2 pircbot
		$a_01_2 = {2e 3a 3a 5b 6c 34 7a 79 20 76 31 2e 33 5d 3a 3a 2e } //2 .::[l4zy v1.3]::.
		$a_01_3 = {68 74 74 70 3a 2f 2f 68 31 2e 72 69 70 77 61 79 2e 63 6f 6d 2f 73 78 6d 61 73 74 2f 63 6f 6e 66 69 67 2e 70 68 70 } //1 http://h1.ripway.com/sxmast/config.php
		$a_01_4 = {68 74 74 70 3a 2f 2f 73 78 6d 61 73 74 2e 66 72 65 65 30 68 6f 73 74 2e 63 6f 6d 2f 63 6f 6e 66 69 67 2e 70 68 70 } //1 http://sxmast.free0host.com/config.php
		$a_01_5 = {5b 53 59 53 49 4e 46 30 5d 3a 20 5b 43 50 55 5d 3a 20 25 49 36 34 75 4d 48 7a 2e 20 5b 4f 53 5d 3a 20 57 69 6e 64 6f 77 73 20 25 73 20 28 25 64 2e 25 64 2c 20 42 75 69 6c 64 20 25 64 29 2e 20 5b 43 75 72 72 65 6e 74 20 55 73 65 72 5d 3a 20 25 73 2e } //2 [SYSINF0]: [CPU]: %I64uMHz. [OS]: Windows %s (%d.%d, Build %d). [Current User]: %s.
		$a_01_6 = {5b 2d 5d 20 42 6f 74 20 66 61 69 6c 65 64 20 74 6f 20 75 70 64 61 74 65 20 28 69 6e 69 74 69 61 6c 20 72 65 6e 61 6d 65 20 66 61 69 6c 65 64 29 } //2 [-] Bot failed to update (initial rename failed)
		$a_01_7 = {5b 2b 5d 20 50 61 73 73 77 6f 72 64 20 64 75 6d 70 20 63 6f 6d 70 6c 65 74 65 64 } //2 [+] Password dump completed
		$a_01_8 = {5b 2d 5d 20 46 61 69 6c 65 64 20 74 6f 20 64 65 63 72 79 70 74 20 61 20 70 61 73 73 77 6f 72 64 } //2 [-] Failed to decrypt a password
		$a_01_9 = {5b 2d 5d 20 55 6e 61 62 6c 65 20 74 6f 20 64 65 63 72 79 70 74 20 4d 53 4e } //2 [-] Unable to decrypt MSN
		$a_01_10 = {50 61 73 73 70 6f 72 74 2e 4e 65 74 5c 2a } //2 Passport.Net\*
		$a_01_11 = {5b 61 75 74 6f 72 75 6e 5d } //1 [autorun]
		$a_01_12 = {46 6c 6f 6f 64 20 73 74 61 72 74 65 64 } //2 Flood started
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2+(#a_01_9  & 1)*2+(#a_01_10  & 1)*2+(#a_01_11  & 1)*1+(#a_01_12  & 1)*2) >=16
 
}