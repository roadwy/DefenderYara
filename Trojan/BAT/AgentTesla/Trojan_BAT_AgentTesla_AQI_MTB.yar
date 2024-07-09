
rule Trojan_BAT_AgentTesla_AQI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AQI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {11 01 11 03 16 11 04 6f ?? ?? ?? 0a ?? ?? ?? ?? ?? 11 01 6f ?? ?? ?? 0a 13 05 ?? ?? ?? ?? ?? 11 02 11 03 16 11 03 8e 69 ?? ?? ?? ?? ?? 13 04 ?? ?? ?? ?? ?? 11 04 11 03 8e 69 } //1
		$a_01_1 = {43 6f 6e 76 65 72 74 6f 72 00 42 79 74 65 } //1 潃癮牥潴r祂整
		$a_01_2 = {43 6c 61 73 73 4c 69 62 72 61 72 79 2e 64 6c 6c } //1 ClassLibrary.dll
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}