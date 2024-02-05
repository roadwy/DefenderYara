
rule Trojan_Win32_DorkBot_DSK_MTB{
	meta:
		description = "Trojan:Win32/DorkBot.DSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {8b 45 ec 8b 4d dc 0f b7 14 41 0f be 45 ab 0f af 45 d8 0f be 4d ab 8b 75 d8 2b f1 33 c6 03 d0 88 55 cf } //02 00 
		$a_02_1 = {0f b6 08 0f be 95 90 01 02 ff ff 0f af 95 90 01 02 ff ff 0f be 85 90 01 02 ff ff 8b b5 90 01 02 ff ff 2b f0 33 d6 03 ca 8b 15 90 01 04 03 95 90 01 02 ff ff 88 0a 90 00 } //02 00 
		$a_02_2 = {8b 4d cc 0f b6 91 90 01 04 c7 45 c4 90 01 04 8b 45 d4 0f b6 88 90 01 04 33 ca 8b 55 d4 89 4d ac 88 8a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}