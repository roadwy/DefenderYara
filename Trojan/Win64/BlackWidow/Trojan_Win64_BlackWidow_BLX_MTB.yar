
rule Trojan_Win64_BlackWidow_BLX_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.BLX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {66 0f 38 1d e0 66 0f 6f c8 44 30 14 0f 66 0f 6c d7 66 0f 38 30 c1 66 0f 38 1d c1 66 0f 6f cd } //5
		$a_01_1 = {66 0f 6d da 66 0f 6c e3 48 ff c1 66 0f 6f d1 66 0f 38 30 c1 } //4
		$a_01_2 = {66 0f 6f d8 48 89 c8 66 0f 69 d0 66 0f 6c d1 } //3
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*4+(#a_01_2  & 1)*3) >=12
 
}