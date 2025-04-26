
rule Trojan_BAT_ZgRAT_C_MTB{
	meta:
		description = "Trojan:BAT/ZgRAT.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {20 00 01 00 00 14 14 11 06 74 } //2
		$a_01_1 = {4e 42 4e 4e 68 48 38 37 33 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //2 NBNNhH873.g.resources
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}