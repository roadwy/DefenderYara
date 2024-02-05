
rule Trojan_Win32_Ursnif_AVA_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.AVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {8b c3 0f b7 f3 2b 44 24 18 81 c1 8c cb c5 01 83 e8 } //01 00 
		$a_02_1 = {83 c5 04 03 05 90 01 04 03 d8 6a 08 5a 81 fd 86 23 00 00 0f 82 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}