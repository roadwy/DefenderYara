
rule Trojan_Win32_Fariet_Inj_MTB{
	meta:
		description = "Trojan:Win32/Fariet.Inj!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 07 09 c0 74 3c 8b 5f 04 8d 84 30 3c 93 0a 00 01 f3 50 83 c7 08 ff 96 dc 93 0a 00 95 8a 07 47 08 c0 74 dc } //01 00 
		$a_01_1 = {8b 45 f0 89 45 ec 8b 45 fc 03 45 ec 73 05 e8 a9 43 f9 ff c6 00 b7 ff 45 f0 ff 4d e8 75 e2 } //00 00 
	condition:
		any of ($a_*)
 
}