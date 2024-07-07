
rule Trojan_BAT_AgentTesla_GDC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {20 16 f0 00 00 0c 2b 18 00 7e 90 01 03 04 07 08 20 00 01 00 00 28 90 01 03 06 0b 00 08 15 58 0c 08 16 fe 04 16 fe 01 0d 09 2d dd 90 00 } //1
		$a_01_1 = {50 00 6c 00 69 00 6e 00 71 00 4f 00 6e 00 53 00 74 00 61 00 63 00 6b 00 4f 00 76 00 65 00 72 00 66 00 6c 00 6f 00 77 00 } //1 PlinqOnStackOverflow
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}