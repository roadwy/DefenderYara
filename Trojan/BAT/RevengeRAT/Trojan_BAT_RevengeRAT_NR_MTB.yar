
rule Trojan_BAT_RevengeRAT_NR_MTB{
	meta:
		description = "Trojan:BAT/RevengeRAT.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 07 09 16 20 00 01 00 00 6f 52 06 00 0a 13 04 07 09 16 11 04 6f 0c 05 00 0a 00 11 05 11 04 d6 13 05 11 06 6f 50 06 00 0a 11 05 6a fe 04 13 09 11 09 2c 1e 02 7b 3e 08 00 04 13 0a 11 0a 2c 0f 11 0a 11 06 6f 50 06 00 0a 6f 3a 13 00 06 } //3
		$a_01_1 = {7b 40 08 00 04 13 0d 11 0d 2c 08 11 0d 6f 42 13 00 06 00 17 0a de 3d } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}