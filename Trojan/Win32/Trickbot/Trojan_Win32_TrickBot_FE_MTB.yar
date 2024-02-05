
rule Trojan_Win32_TrickBot_FE_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.FE!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 4d f0 03 4d ec 0f be 11 81 f2 e0 00 00 00 88 55 eb 8b 45 08 03 45 ec 89 45 e4 8b 4d e4 3b 4d f8 73 2d 8b 55 e4 0f b6 02 0f b6 4d eb 33 c1 8b 55 e4 2b 55 08 0f b6 ca 81 e1 e0 00 00 00 33 c1 8b 55 e4 88 02 8b 45 e4 03 45 f4 89 45 e4 eb cb } //00 00 
	condition:
		any of ($a_*)
 
}