
rule Trojan_Win32_Tofsee_CPW_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.CPW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {8b 44 24 28 89 44 24 20 8b 44 24 14 01 44 24 20 8b 4c 24 1c d3 ea 8b 4c 24 38 8d 44 24 24 c7 90 02 0a 89 54 24 24 e8 90 01 04 8b 44 24 20 31 44 24 10 8b 74 24 24 33 74 24 10 81 90 02 0a 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}