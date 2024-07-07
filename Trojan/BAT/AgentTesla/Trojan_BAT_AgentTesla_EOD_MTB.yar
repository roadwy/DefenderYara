
rule Trojan_BAT_AgentTesla_EOD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EOD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 09 20 00 b4 00 00 5d 07 09 20 00 b4 00 00 5d 91 08 09 1f 16 5d 90 01 05 61 6a 07 09 17 58 20 00 b4 00 00 5d 91 90 01 05 6e 59 20 00 01 00 00 6a 58 20 00 01 00 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}