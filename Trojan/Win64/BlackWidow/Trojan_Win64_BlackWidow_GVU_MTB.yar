
rule Trojan_Win64_BlackWidow_GVU_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.GVU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {66 0f f9 d1 49 f7 f0 66 0f 6f c1 } //2
		$a_01_1 = {45 8a 14 11 66 0f 6d ea } //1
		$a_01_2 = {44 30 14 0f 66 0f 6f d8 } //1
		$a_01_3 = {66 0f 6c c2 48 ff c1 66 0f dd e0 } //1
		$a_01_4 = {66 0f 6f d1 48 81 f9 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}