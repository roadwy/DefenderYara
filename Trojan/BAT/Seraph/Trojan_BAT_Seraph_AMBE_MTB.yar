
rule Trojan_BAT_Seraph_AMBE_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AMBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {61 0b 1f f2 13 09 2b 9f 11 06 11 07 11 05 11 07 6f ?? 00 00 0a 20 ?? 0e 00 00 61 d1 9d 1f 0f 13 09 } //1
		$a_03_1 = {06 09 16 07 6f ?? 00 00 0a 26 1e 13 08 2b bd } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}