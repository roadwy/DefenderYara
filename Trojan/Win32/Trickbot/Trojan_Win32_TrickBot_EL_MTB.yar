
rule Trojan_Win32_TrickBot_EL_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.EL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 11 8b c2 8b 4d 08 03 4d f0 33 d2 8a 11 03 c2 33 d2 f7 35 90 01 04 89 55 f8 8b 45 ec 03 05 90 01 04 03 05 90 01 04 2b 05 90 01 04 2b 05 90 01 04 03 05 90 01 04 8b 4d f8 03 0d 90 01 04 8b 15 90 01 04 0f af 15 90 01 04 0f af 15 90 01 04 03 ca 2b 0d 90 01 04 2b 0d 90 01 04 8b 55 0c 8b 75 08 8a 04 02 32 04 0e 8b 4d ec 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}