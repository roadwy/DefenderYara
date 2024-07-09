
rule TrojanDropper_BAT_Azorult_F_MTB{
	meta:
		description = "TrojanDropper:BAT/Azorult.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {00 00 01 25 d0 01 00 00 04 28 21 00 00 0a 73 22 00 00 0a 0a 73 23 00 00 0a [0-20] 73 24 00 00 0a [0-30] 6f 25 00 00 0a 1e 5b 6f 26 00 00 0a 6f 27 00 00 0a [0-30] 6f 28 00 00 0a 1e 5b 6f 26 00 00 0a 6f 29 00 00 0a [0-30] 6f 2a 00 00 0a 17 73 2b 00 00 0a [0-30] 8e 69 6f 2c 00 00 0a } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}