
rule Trojan_AndroidOS_Coper_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Coper.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {c4 10 6a 27 6a 27 57 8d bc 24 bb 01 00 00 57 e8 65 1a 00 00 83 c4 10 6a 27 6a 27 ff 74 24 40 57 e8 54 1a 00 00 83 c4 10 6a 27 6a 27 56 57 e8 46 1a 00 00 83 c4 10 6a 27 6a 27 56 89 fe 57 e8 36 } //1
	condition:
		((#a_00_0  & 1)*1) >=1
 
}