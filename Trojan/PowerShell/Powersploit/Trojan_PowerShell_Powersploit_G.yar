
rule Trojan_PowerShell_Powersploit_G{
	meta:
		description = "Trojan:PowerShell/Powersploit.G,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 06 00 00 "
		
	strings :
		$a_00_0 = {2f 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 6d 00 61 00 66 00 69 00 61 00 2f 00 70 00 6f 00 77 00 65 00 72 00 73 00 70 00 6c 00 6f 00 69 00 74 00 2f 00 } //1 /powershellmafia/powersploit/
		$a_00_1 = {2f 00 70 00 65 00 65 00 77 00 70 00 77 00 2f 00 69 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 77 00 63 00 6d 00 64 00 75 00 6d 00 70 00 2f 00 } //1 /peewpw/invoke-wcmdump/
		$a_00_2 = {2f 00 6d 00 61 00 74 00 74 00 69 00 66 00 65 00 73 00 74 00 61 00 74 00 69 00 6f 00 6e 00 2f 00 70 00 6f 00 77 00 65 00 72 00 73 00 70 00 6c 00 6f 00 69 00 74 00 2f 00 } //1 /mattifestation/powersploit/
		$a_00_3 = {2f 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 65 00 6d 00 70 00 69 00 72 00 65 00 2f 00 } //1 /powershellempire/
		$a_00_4 = {2f 00 50 00 6f 00 77 00 65 00 72 00 50 00 69 00 63 00 6b 00 2f 00 50 00 53 00 49 00 6e 00 6a 00 65 00 63 00 74 00 6f 00 72 00 2f 00 } //1 /PowerPick/PSInjector/
		$a_00_5 = {2f 00 6d 00 61 00 73 00 74 00 65 00 72 00 2f 00 50 00 6f 00 77 00 65 00 72 00 55 00 70 00 2f 00 50 00 6f 00 77 00 65 00 72 00 55 00 70 00 2e 00 } //1 /master/PowerUp/PowerUp.
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=1
 
}