
rule Trojan_BAT_AgentTesla_JOK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JOK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 06 08 18 5a 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a d2 6f 90 01 03 0a 08 17 58 0c 08 06 6f 90 01 03 0a 18 5b fe 04 0d 09 2d d5 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}