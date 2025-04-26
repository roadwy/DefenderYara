
rule Trojan_BAT_AgentTesla_ABFM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0d 09 07 6f ?? ?? ?? 0a 00 09 18 6f ?? ?? ?? 0a 00 09 6f ?? ?? ?? 0a 13 04 11 04 03 16 03 8e 69 6f ?? ?? ?? 0a 13 05 09 6f ?? ?? ?? 0a 00 11 05 0a 2b 00 06 2a } //1
		$a_01_1 = {43 00 6f 00 6f 00 6c 00 65 00 72 00 4d 00 61 00 73 00 74 00 65 00 72 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 CoolerMaster.Resources
		$a_01_2 = {48 00 53 00 6c 00 57 00 56 00 78 00 47 00 65 00 72 00 } //1 HSlWVxGer
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}