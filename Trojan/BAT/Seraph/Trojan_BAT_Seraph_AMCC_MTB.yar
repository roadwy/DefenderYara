
rule Trojan_BAT_Seraph_AMCC_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AMCC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 11 06 28 90 01 01 00 00 0a 16 14 28 90 01 01 00 00 06 00 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 00 dd 90 00 } //1
		$a_03_1 = {06 1f 20 58 28 90 01 01 00 00 0a 52 06 1f 20 58 46 2c 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}