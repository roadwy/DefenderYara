
rule Trojan_BAT_Seraph_AYMA_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AYMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 11 00 91 13 02 38 ?? 00 00 00 03 8e 69 17 59 13 01 20 04 00 00 00 38 ?? ff ff ff 11 00 17 58 13 00 38 ?? 00 00 00 03 11 00 03 11 01 91 9c 38 ?? 00 00 00 11 01 17 59 13 01 20 01 00 00 00 7e } //4
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}