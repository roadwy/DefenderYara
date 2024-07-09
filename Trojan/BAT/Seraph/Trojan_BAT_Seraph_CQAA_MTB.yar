
rule Trojan_BAT_Seraph_CQAA_MTB{
	meta:
		description = "Trojan:BAT/Seraph.CQAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff ff 11 00 16 11 00 8e 69 28 ?? 00 00 0a 20 } //4
		$a_01_1 = {52 65 76 65 72 73 65 } //1 Reverse
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}