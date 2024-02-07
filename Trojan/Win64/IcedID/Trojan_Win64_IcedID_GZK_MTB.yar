
rule Trojan_Win64_IcedID_GZK_MTB{
	meta:
		description = "Trojan:Win64/IcedID.GZK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {49 8b c6 4d 8d 40 90 01 01 48 f7 e1 41 ff c1 48 c1 ea 90 01 01 48 6b c2 90 01 01 48 2b c8 0f b6 44 8c 90 01 01 41 30 40 90 01 01 49 63 c9 48 81 f9 90 01 04 72 d3 90 00 } //01 00 
		$a_01_1 = {6f 6b 6c 77 70 62 72 77 6f 79 69 73 62 } //01 00  oklwpbrwoyisb
		$a_01_2 = {71 66 72 66 71 61 7a 64 76 74 } //01 00  qfrfqazdvt
		$a_01_3 = {6e 78 79 61 6c 6f 69 64 67 72 } //00 00  nxyaloidgr
	condition:
		any of ($a_*)
 
}