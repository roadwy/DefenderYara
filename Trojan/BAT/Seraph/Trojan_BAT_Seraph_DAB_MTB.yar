
rule Trojan_BAT_Seraph_DAB_MTB{
	meta:
		description = "Trojan:BAT/Seraph.DAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 1e 58 16 54 2b 24 08 06 1e 58 4a 18 5b 07 06 1e 58 4a 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a 9c 06 1e 58 06 1e 58 4a 18 58 54 06 1e 58 4a 06 1a 58 4a 32 d2 90 00 } //4
		$a_01_1 = {54 6f 42 79 74 65 } //1 ToByte
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}