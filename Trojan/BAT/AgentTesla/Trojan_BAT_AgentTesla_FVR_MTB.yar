
rule Trojan_BAT_AgentTesla_FVR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.FVR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {25 47 02 08 1f 10 5d 91 61 d2 52 00 08 17 d6 0c 08 07 fe 02 16 fe 01 0d 09 2d dd } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}