
rule Trojan_Win32_Dridex_EC_MTB{
	meta:
		description = "Trojan:Win32/Dridex.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 08 00 00 03 00 "
		
	strings :
		$a_80_0 = {47 65 29 4d 6f 64 20 6c 65 48 } //Ge)Mod leH  03 00 
		$a_80_1 = {4c 62 72 61 47 79 45 78 34 } //LbraGyEx4  03 00 
		$a_80_2 = {26 54 68 75 73 20 70 3e 67 67 72 3d 69 20 63 3d 6a 6e 6f 40 20 62 65 6c 72 75 6e 7c 6d 6e } //&Thus p>ggr=i c=jno@ belrun|mn  03 00 
		$a_80_3 = {49 4f 62 69 74 } //IObit  03 00 
		$a_80_4 = {4d 61 69 6c 41 73 53 6d 74 70 53 65 72 76 65 72 } //MailAsSmtpServer  03 00 
		$a_80_5 = {55 70 6c 6f 61 64 56 69 61 48 74 74 70 } //UploadViaHttp  03 00 
		$a_80_6 = {62 75 67 72 65 70 6f 72 74 2e 74 78 74 } //bugreport.txt  03 00 
		$a_80_7 = {73 63 72 65 65 6e 73 68 6f 74 2e 70 6e 67 } //screenshot.png  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Dridex_EC_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.EC!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {b0 e5 c6 44 24 33 74 8a 4c 24 33 8a 54 24 1f 88 54 24 51 38 c8 0f 84 17 ff ff ff eb 89 31 c0 c7 44 24 2c 1e 06 } //00 00 
	condition:
		any of ($a_*)
 
}