
rule Trojan_BAT_XWorm_MBXV_MTB{
	meta:
		description = "Trojan:BAT/XWorm.MBXV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {20 a0 00 00 00 91 61 20 94 00 00 00 5f 9c } //2
		$a_01_1 = {41 63 33 79 4a 5a 35 44 63 57 6b 68 5a 5a 31 35 57 34 } //1 Ac3yJZ5DcWkhZZ15W4
		$a_01_2 = {30 31 66 62 66 33 31 62 35 33 61 31 } //1 01fbf31b53a1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}