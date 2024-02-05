
rule Trojan_BAT_AgentTesla_MBCX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBCX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {72 db 0e 00 70 06 72 e9 0e 00 70 7e 90 01 04 28 90 01 03 06 72 f1 0e 00 70 72 f5 0e 00 70 90 00 } //01 00 
		$a_03_1 = {16 91 13 05 08 17 8d 90 01 01 00 00 01 25 16 11 05 9c 6f 90 01 01 00 00 0a 09 18 58 0d 09 07 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}