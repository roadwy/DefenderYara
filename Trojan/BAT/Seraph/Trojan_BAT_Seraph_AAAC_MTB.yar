
rule Trojan_BAT_Seraph_AAAC_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AAAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {14 0a 00 73 ?? 00 00 0a 0b 28 ?? 00 00 06 0a de 07 07 6f ?? 00 00 0a dc 06 28 ?? 00 00 2b 28 ?? 00 00 2b 0a de 03 26 de d9 } //4
		$a_01_1 = {52 65 76 65 72 73 65 } //1 Reverse
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}