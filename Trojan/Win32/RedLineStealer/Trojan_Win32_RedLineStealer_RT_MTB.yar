
rule Trojan_Win32_RedLineStealer_RT_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,2c 00 2c 00 09 00 00 0a 00 "
		
	strings :
		$a_81_0 = {50 61 73 73 77 6f 72 64 20 5c 20 50 61 73 73 20 70 68 72 61 73 65 20 74 6f 20 62 65 20 74 65 73 74 65 64 } //0a 00 
		$a_81_1 = {47 65 6e 65 72 61 74 65 64 20 50 61 73 73 77 6f 72 64 20 5c 20 50 61 73 73 70 68 72 61 73 65 } //0a 00 
		$a_81_2 = {5a 6f 6d 62 69 65 5f 47 65 74 54 79 70 65 49 6e 66 6f } //0a 00 
		$a_81_3 = {46 2a 5c 41 44 3a 5c 4a 75 6e 6b 20 50 72 6f 67 72 61 6d 73 5c 54 65 73 74 5f 50 61 73 73 77 32 30 32 34 33 32 35 32 30 31 37 5c 54 65 73 74 50 77 64 5c 54 65 73 74 50 77 64 2e 76 62 70 } //0a 00 
		$a_81_4 = {4b 65 6e 6e 65 74 68 20 49 76 65 73 20 6b 65 6e 61 73 6f 40 74 78 2e 72 72 2e 63 6f 6d } //01 00 
		$a_81_5 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //01 00 
		$a_81_6 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //01 00 
		$a_81_7 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //01 00 
		$a_81_8 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_RedLineStealer_RT_MTB_2{
	meta:
		description = "Trojan:Win32/RedLineStealer.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 09 00 00 01 00 "
		
	strings :
		$a_80_0 = {4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 57 69 6e 64 6f 77 73 20 4e 54 20 36 2e 31 3b 20 57 69 6e 36 34 3b 20 78 36 34 29 20 41 70 70 6c 65 57 65 62 4b 69 74 2f 35 33 37 2e 33 36 20 28 4b 48 54 4d 4c 2c 20 6c 69 6b 65 20 47 65 63 6b 6f 29 20 43 68 72 6f 6d 65 2f 37 33 2e 30 2e 33 36 38 33 2e 38 36 20 53 61 66 61 72 69 2f 35 33 37 2e 33 36 } //Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.86 Safari/537.36  01 00 
		$a_80_1 = {68 74 74 70 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //http\shell\open\command  01 00 
		$a_80_2 = {63 68 61 6e 6e 65 6c 69 6e 66 6f 2e 70 77 2f } //channelinfo.pw/  01 00 
		$a_80_3 = {5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 43 6f 6f 6b 69 65 73 } //\Google\Chrome\User Data\Default\Cookies  01 00 
		$a_80_4 = {5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c 50 72 6f 66 69 6c 65 20 31 5c 4c 6f 67 69 6e 20 44 61 74 61 } //\Google\Chrome\User Data\Profile 1\Login Data  01 00 
		$a_80_5 = {4c 6f 67 69 6e 4e 61 6d 65 } //LoginName  01 00 
		$a_80_6 = {41 63 63 6f 75 6e 74 53 74 61 74 75 73 } //AccountStatus  01 00 
		$a_80_7 = {74 70 79 79 66 2e 63 6f 6d } //tpyyf.com  01 00 
		$a_80_8 = {43 72 65 64 69 74 43 61 72 64 } //CreditCard  00 00 
	condition:
		any of ($a_*)
 
}