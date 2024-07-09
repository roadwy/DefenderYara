
rule Trojan_BAT_AgentTesla_COL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.COL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {08 09 9a 13 04 00 06 11 04 1f 10 28 ?? ?? ?? 0a d1 13 05 12 05 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0a 00 09 17 58 0d } //1
		$a_01_1 = {52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 5f 00 4d 00 65 00 74 00 65 00 72 00 } //1 Resource_Meter
		$a_01_2 = {47 65 74 54 79 70 65 } //1 GetType
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}