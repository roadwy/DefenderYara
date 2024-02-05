
rule Trojan_Win64_Totbrick_B{
	meta:
		description = "Trojan:Win64/Totbrick.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 c7 45 af 48 b9 66 c7 45 b9 48 b8 66 c7 45 c3 ff e0 } //01 00 
		$a_01_1 = {41 03 48 fc 3b d1 72 1c 41 ff c2 49 83 c0 28 45 3b d3 7c e5 } //00 00 
	condition:
		any of ($a_*)
 
}