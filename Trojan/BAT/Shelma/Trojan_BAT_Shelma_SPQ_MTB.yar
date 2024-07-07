
rule Trojan_BAT_Shelma_SPQ_MTB{
	meta:
		description = "Trojan:BAT/Shelma.SPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 08 11 09 07 11 09 9a 1f 10 28 10 00 00 0a 9c 00 11 09 17 58 13 09 11 09 07 8e 69 fe 04 13 0a 11 0a 2d dc } //5
		$a_81_1 = {32 30 32 32 31 32 31 33 2e 70 64 62 } //1 20221213.pdb
	condition:
		((#a_01_0  & 1)*5+(#a_81_1  & 1)*1) >=6
 
}