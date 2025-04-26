
rule Trojan_AndroidOS_Wroba_L_MTB{
	meta:
		description = "Trojan:AndroidOS/Wroba.L!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {3b 00 17 4c 67 ?? ?? ?? ?? ?? ?? 2f ?? ?? 41 70 70 6c 69 63 61 74 69 6f 6e 3b 00 } //1
		$a_01_1 = {00 02 6a 7a 00 02 6b 67 00 0b 6c 6f 61 64 4c 69 62 72 61 72 79 00 02 6c 73 00 02 6d 79 00 } //1
		$a_01_2 = {3b 00 06 4c 73 2f 6e 69 3b 00 } //1 ;䰆⽳楮;
		$a_01_3 = {69 73 49 67 6e 6f 72 69 6e 67 42 61 74 74 65 72 79 4f 70 74 69 6d 69 7a 61 74 69 6f 6e 73 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}