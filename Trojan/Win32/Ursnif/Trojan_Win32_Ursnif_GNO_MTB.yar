
rule Trojan_Win32_Ursnif_GNO_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.GNO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b 11 8b de 2b df 03 d3 89 11 83 c1 90 01 01 48 8b fa 90 00 } //0a 00 
		$a_03_1 = {69 c0 0d 66 19 00 05 5f f3 6e 3c a3 90 01 04 0f b7 c0 6a 19 99 5b f7 fb 80 c2 61 88 14 31 41 3b cf 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}