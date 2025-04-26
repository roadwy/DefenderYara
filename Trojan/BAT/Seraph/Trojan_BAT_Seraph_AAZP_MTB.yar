
rule Trojan_BAT_Seraph_AAZP_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AAZP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {11 05 11 01 11 06 59 17 59 11 03 9c } //2
		$a_01_1 = {11 05 11 06 11 05 11 01 11 06 59 17 59 91 9c } //2
		$a_01_2 = {47 65 74 42 79 74 65 41 72 72 61 79 41 73 79 6e 63 } //1 GetByteArrayAsync
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}