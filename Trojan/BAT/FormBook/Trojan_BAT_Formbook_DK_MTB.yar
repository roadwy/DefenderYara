
rule Trojan_BAT_Formbook_DK_MTB{
	meta:
		description = "Trojan:BAT/Formbook.DK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {24 65 31 39 63 38 31 62 31 2d 33 37 65 63 2d 34 62 62 61 2d 38 38 64 65 2d 62 61 34 64 64 63 65 32 30 61 30 31 } //1 $e19c81b1-37ec-4bba-88de-ba4ddce20a01
		$a_81_1 = {73 63 72 65 65 6e 63 61 70 74 75 72 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 screencapture.Properties.Resources
		$a_81_2 = {51 75 69 74 3a 20 43 74 72 6c 20 2b 20 41 6c 74 20 2b 20 53 68 69 66 74 20 2b 20 51 } //1 Quit: Ctrl + Alt + Shift + Q
		$a_81_3 = {61 75 74 6f 72 65 73 74 61 72 74 } //1 autorestart
		$a_81_4 = {67 65 74 5f 46 74 70 41 64 64 72 65 73 73 } //1 get_FtpAddress
		$a_81_5 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}