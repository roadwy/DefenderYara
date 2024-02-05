
rule Trojan_Win32_Ursnif_BB_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 4c 24 10 81 c5 90 01 04 0f b7 f0 89 2d 90 01 04 89 29 8d 6e 90 01 01 8d 4d 90 01 01 03 ce 90 00 } //01 00 
		$a_02_1 = {69 4c 24 20 90 01 04 83 44 24 10 90 01 01 8d 0c 69 8b 2d 90 01 04 2b ce ff 4c 24 14 8b 35 90 00 } //00 00 
		$a_00_2 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}