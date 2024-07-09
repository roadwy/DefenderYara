
rule Trojan_BAT_AgentTesla_ASFG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASFG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 08 18 5b 02 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a d2 9c 08 18 58 0c 08 06 fe 04 0d 09 2d } //1
		$a_01_1 = {57 69 6e 64 6f 77 73 5f 50 75 72 73 75 69 74 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 Windows_Pursuit.Properties.Resources
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}