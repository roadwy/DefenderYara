
rule Trojan_Win32_Azorult_BD_MTB{
	meta:
		description = "Trojan:Win32/Azorult.BD!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {55 8b ec 51 c7 45 fc 02 00 00 00 8b 45 0c 90 01 45 fc 83 6d fc 02 8b 45 08 8b 08 33 4d fc 8b 55 08 89 0a 8b e5 5d c2 08 00 } //0a 00 
		$a_01_1 = {8b 4d a8 d3 e8 89 45 ec 8b 4d ec 03 4d d4 } //00 00 
	condition:
		any of ($a_*)
 
}