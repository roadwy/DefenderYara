
rule Trojan_Win32_Raccoon_CP_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.CP!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 04 8b 01 89 44 24 04 8b 44 24 08 01 44 24 04 8b 54 24 04 89 11 } //00 00 
	condition:
		any of ($a_*)
 
}