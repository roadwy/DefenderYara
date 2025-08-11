
rule Trojan_Python_Stealga_DB_MTB{
	meta:
		description = "Trojan:Python/Stealga.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,37 00 37 00 0a 00 00 "
		
	strings :
		$a_81_0 = {43 6f 6f 6b 69 65 73 50 61 72 73 65 73 } //10 CookiesParses
		$a_81_1 = {43 68 72 6f 6d 69 75 6d } //10 Chromium
		$a_81_2 = {70 61 73 73 2e 68 74 6d 6c } //10 pass.html
		$a_81_3 = {50 43 2e 68 74 6d 6c } //10 PC.html
		$a_81_4 = {63 6f 6f 6b 69 65 73 2e 7a 69 70 } //10 cookies.zip
		$a_81_5 = {67 65 74 5f 70 61 73 73 77 6f 72 64 73 } //1 get_passwords
		$a_81_6 = {67 65 74 5f 63 6f 6f 6b 69 65 73 } //1 get_cookies
		$a_81_7 = {67 65 74 5f 77 69 66 69 } //1 get_wifi
		$a_81_8 = {67 65 74 5f 6d 61 63 } //1 get_mac
		$a_81_9 = {67 65 74 65 6e 76 } //1 getenv
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*10+(#a_81_2  & 1)*10+(#a_81_3  & 1)*10+(#a_81_4  & 1)*10+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=55
 
}