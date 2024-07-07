
rule Trojan_BAT_RemcosRAT_NRR_MTB{
	meta:
		description = "Trojan:BAT/RemcosRAT.NRR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {7e 17 00 00 04 02 17 58 91 1f 10 62 60 0a 06 7e 90 01 01 00 00 04 02 18 58 91 1e 62 60 0a 06 7e 90 01 01 00 00 04 02 19 58 91 60 0a 02 1a 58 fe 90 01 02 00 06 17 2f 06 7e 90 01 01 00 00 0a 2a 90 00 } //5
		$a_01_1 = {35 41 73 73 65 6d 62 6c 65 64 2e 50 72 6f 67 72 61 6d } //1 5Assembled.Program
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}