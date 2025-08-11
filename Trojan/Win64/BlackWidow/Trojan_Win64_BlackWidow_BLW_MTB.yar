
rule Trojan_Win64_BlackWidow_BLW_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.BLW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {66 0f fd c1 66 0f f9 d0 66 0f 6f cd 44 30 14 0f 66 0f 6c ca 66 0f fd da 66 0f f9 d0 66 0f 69 d0 66 0f 6f c3 66 0f 6c d3 66 0f 6d cf } //5
		$a_01_1 = {66 0f f9 d0 48 ff c1 66 0f f9 cb 66 0f 6d cc } //4
		$a_01_2 = {66 0f fd da 48 89 c8 66 0f 6f c1 } //3
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*4+(#a_01_2  & 1)*3) >=12
 
}