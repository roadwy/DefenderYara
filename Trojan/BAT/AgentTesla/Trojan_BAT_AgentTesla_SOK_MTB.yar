
rule Trojan_BAT_AgentTesla_SOK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SOK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_81_0 = {43 45 50 5a 36 37 35 52 52 37 46 50 37 47 51 37 44 45 5a 59 38 48 } //1 CEPZ675RR7FP7GQ7DEZY8H
		$a_00_1 = {00 11 07 11 12 58 20 00 01 00 00 5d 13 13 00 11 12 17 58 13 12 11 12 19 fe 04 13 14 11 14 2d e0 } //1
	condition:
		((#a_81_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}