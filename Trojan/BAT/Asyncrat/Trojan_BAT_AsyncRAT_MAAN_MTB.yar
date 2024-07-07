
rule Trojan_BAT_AsyncRAT_MAAN_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.MAAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0d 2b 1e 08 09 9a fe 06 c9 00 00 06 73 90 01 01 00 00 0a 07 6f 90 01 01 01 00 06 28 90 01 01 00 00 0a 26 09 17 58 0d 09 08 8e 69 32 dc 90 00 } //1
		$a_01_1 = {41 00 73 00 79 00 6e 00 63 00 52 00 41 00 54 00 } //1 AsyncRAT
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}