
rule Trojan_BAT_Redline_AB_MTB{
	meta:
		description = "Trojan:BAT/Redline.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 25 00 00 01 0a 02 1b 06 16 02 8e 69 1b 59 28 63 00 00 0a 06 16 14 28 33 00 00 06 0b 25 03 6f 64 00 00 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_BAT_Redline_AB_MTB_2{
	meta:
		description = "Trojan:BAT/Redline.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_81_0 = {77 6f 72 6b 5c 49 6d 61 67 65 52 65 73 69 7a 65 54 65 73 74 5c 67 65 6f 2d 65 6c 65 76 61 74 69 6f 6e 2e 70 6e 67 } //2 work\ImageResizeTest\geo-elevation.png
		$a_00_1 = {63 72 65 61 74 65 64 65 63 72 79 70 74 6f 72 } //1 createdecryptor
		$a_00_2 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_00_3 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_00_4 = {64 65 62 75 67 67 65 72 6e 6f 6e 75 73 65 72 63 6f 64 65 61 74 74 72 69 62 75 74 65 } //1 debuggernonusercodeattribute
		$a_00_5 = {54 72 69 70 6c 65 44 45 53 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //1 TripleDESCryptoServiceProvider
	condition:
		((#a_81_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=7
 
}