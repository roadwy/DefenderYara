
rule Trojan_Win32_Tofsee_MK_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b d6 d3 ea 03 d5 89 54 24 90 01 01 8b 44 24 90 01 01 31 44 24 90 01 01 8b 44 24 90 01 01 31 44 24 90 01 01 8b 44 24 90 01 01 89 44 24 90 01 01 8b 44 24 90 01 01 29 44 24 90 01 01 8b 44 24 90 01 01 89 44 24 90 01 01 8d 44 24 90 01 01 e8 90 01 04 83 ef 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}