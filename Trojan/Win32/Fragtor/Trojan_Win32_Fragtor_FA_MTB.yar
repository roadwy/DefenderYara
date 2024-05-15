
rule Trojan_Win32_Fragtor_FA_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.FA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {0f b6 84 05 90 01 04 03 c8 0f b6 c1 8b 4d 08 8a 84 05 90 01 04 30 04 0a 42 89 55 0c 3b 55 90 00 } //01 00 
		$a_01_1 = {62 73 69 6f 75 65 67 6a 68 65 73 75 68 67 5f 73 61 65 67 69 75 65 61 73 68 } //00 00  bsiouegjhesuhg_saegiueash
	condition:
		any of ($a_*)
 
}