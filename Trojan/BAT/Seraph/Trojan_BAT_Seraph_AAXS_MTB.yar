
rule Trojan_BAT_Seraph_AAXS_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AAXS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {14 0a 00 28 0e 00 00 06 0a 06 16 06 8e 69 28 01 00 00 0a 06 0b dd 03 00 00 00 26 de e5 } //4
		$a_01_1 = {52 65 76 65 72 73 65 } //1 Reverse
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}