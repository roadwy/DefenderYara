
rule Trojan_Win32_Ursnif_DJ_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.DJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 54 24 79 68 72 74 67 66 64 72 34 68 65 72 79 } //01 00  CT$yhrtgfdr4hery
		$a_01_1 = {79 50 74 6e 48 4d 67 2e 70 64 62 } //01 00  yPtnHMg.pdb
		$a_81_2 = {79 69 73 67 6c 61 6e 64 2e 6d } //01 00  yisgland.m
		$a_81_3 = {43 61 74 74 6c 65 63 6c 65 73 73 65 72 71 6d 65 51 } //01 00  CattleclesserqmeQ
		$a_81_4 = {67 69 76 65 6c 65 74 64 6f 6e 2e 74 74 77 6f 2e 70 } //00 00  giveletdon.ttwo.p
	condition:
		any of ($a_*)
 
}