
rule Trojan_Win32_Bulta_RPY_MTB{
	meta:
		description = "Trojan:Win32/Bulta.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {03 4c 24 20 8b d0 c1 ea 05 03 54 24 24 03 c5 33 d1 33 d0 2b fa 8b cf c1 e1 04 81 3d } //01 00 
		$a_01_1 = {8b 84 24 74 08 00 00 8b 54 24 14 89 78 04 5f 5e 5d 89 10 5b } //00 00 
	condition:
		any of ($a_*)
 
}