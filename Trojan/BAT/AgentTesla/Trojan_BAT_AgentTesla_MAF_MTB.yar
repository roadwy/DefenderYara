
rule Trojan_BAT_AgentTesla_MAF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 05 00 "
		
	strings :
		$a_01_0 = {11 09 11 09 09 94 11 09 11 05 94 58 20 00 01 00 00 5d 94 13 06 11 0a 11 04 07 11 04 91 11 06 61 d2 9c 11 04 } //02 00 
		$a_01_1 = {33 63 33 37 30 62 39 36 2d 63 37 37 34 2d 34 62 63 32 2d 39 39 61 34 2d 63 39 31 35 30 37 35 33 34 62 33 64 } //01 00 
		$a_01_2 = {49 6e 76 6f 6b 65 } //00 00 
	condition:
		any of ($a_*)
 
}