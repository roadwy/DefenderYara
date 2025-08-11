
rule Trojan_Win64_BlackWidow_GVW_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.GVW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {66 0f fd c2 45 8a 14 11 66 0f 38 30 c1 } //2
		$a_01_1 = {66 0f 69 d0 44 30 14 0f 66 0f 6f cb } //1
		$a_01_2 = {66 0f 62 c2 48 ff c1 66 0f dd e6 } //1
		$a_01_3 = {66 0f 6c d1 48 89 c8 66 0f dd e0 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}