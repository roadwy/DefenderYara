
rule Trojan_BAT_AgentTesla_OI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.OI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {06 09 91 7e [0-04] 7e [0-04] 6f [0-04] 74 [0-04] 07 09 28 [0-04] 9c 09 17 d6 0d 09 08 31 [0-01] 7e [0-04] 7e [0-04] 06 6f [0-05] 73 [0-04] 20 [0-04] 20 [0-04] 6f [0-04] 28 [0-04] 6f [0-05] 28 [0-05] 2a } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}