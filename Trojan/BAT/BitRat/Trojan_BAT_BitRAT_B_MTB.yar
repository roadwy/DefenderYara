
rule Trojan_BAT_BitRAT_B_MTB{
	meta:
		description = "Trojan:BAT/BitRAT.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {64 64 66 66 72 64 6a 66 66 66 73 66 66 68 67 64 66 66 61 66 63 66 64 73 73 66 6b 66 68 67 6a } //2 ddffrdjfffsffhgdffafcfdssfkfhgj
		$a_01_1 = {68 64 66 66 68 64 66 73 64 68 64 66 66 64 66 6b 64 66 } //2 hdffhdfsdhdffdfkdf
		$a_01_2 = {66 64 64 73 66 66 66 68 73 73 } //2 fddsfffhss
		$a_01_3 = {66 73 66 66 66 61 66 61 64 } //2 fsfffafad
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}