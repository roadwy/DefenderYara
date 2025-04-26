
rule Trojan_AndroidOS_Joker_B_MTB{
	meta:
		description = "Trojan:AndroidOS/Joker.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {67 64 2d 31 33 30 31 34 37 36 32 39 36 2e 63 6f 73 2e 6e 61 2d 74 6f 72 6f 6e 74 6f 2e 6d 79 71 63 6c 6f 75 64 2e 63 6f 6d } //3 gd-1301476296.cos.na-toronto.myqcloud.com
		$a_01_1 = {62 61 6f 62 75 74 6f 6e 67 } //1 baobutong
		$a_01_2 = {62 70 69 6c 6f 6e 67 } //1 bpilong
		$a_01_3 = {70 6f 72 6f 63 } //1 poroc
	condition:
		((#a_00_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}