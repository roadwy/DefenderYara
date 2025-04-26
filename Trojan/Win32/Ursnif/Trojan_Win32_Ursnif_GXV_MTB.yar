
rule Trojan_Win32_Ursnif_GXV_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.GXV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 24 17 00 08 33 48 1a 24 48 48 24 83 4c ff cc 10 4c c4 83 60 3b cc 8b 4c 20 cc 04 00 48 00 61 93 cc 24 8b 00 09 } //5
		$a_01_1 = {30 58 17 24 cc b0 48 } //5
		$a_01_2 = {54 6f 77 61 72 64 64 69 66 66 69 63 75 6c 74 } //1 Towarddifficult
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1) >=11
 
}