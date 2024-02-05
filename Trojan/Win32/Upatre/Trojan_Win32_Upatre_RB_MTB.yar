
rule Trojan_Win32_Upatre_RB_MTB{
	meta:
		description = "Trojan:Win32/Upatre.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 43 01 0f b6 d8 8a 14 3b 0f b6 c2 03 c1 0f b6 c8 89 4d f8 0f b6 04 39 88 04 3b 88 14 39 0f b6 0c 3b 0f b6 c2 03 c8 90 01 0f 41 0f b6 04 39 8b 4d fc 30 04 0e 46 8b 4d f8 3b 75 08 72 b6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}