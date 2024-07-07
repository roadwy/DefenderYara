
rule Trojan_BAT_BitRAT_C_MTB{
	meta:
		description = "Trojan:BAT/BitRAT.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 00 0a 13 06 7e 90 01 01 00 00 04 11 06 08 28 90 01 01 00 00 06 7e 90 01 01 00 00 04 11 06 18 28 90 01 01 00 00 06 7e 90 01 01 00 00 04 11 06 18 28 90 01 01 00 00 06 11 06 0d 90 00 } //2
		$a_01_1 = {61 00 73 00 70 00 6e 00 65 00 74 00 5f 00 77 00 70 00 } //2 aspnet_wp
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}