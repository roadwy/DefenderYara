
rule Trojan_BAT_AgentTesla_CMS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CMS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {08 09 9a 13 04 00 06 11 04 1f 10 28 ?? ?? ?? 0a d1 13 05 12 05 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0a 00 09 17 58 0d } //1
		$a_01_1 = {54 6f 55 49 6e 74 33 32 } //1 ToUInt32
		$a_01_2 = {52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 5f 00 4d 00 65 00 74 00 65 00 72 00 } //1 Resource_Meter
		$a_01_3 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_4 = {54 6f 43 68 61 72 41 72 72 61 79 } //1 ToCharArray
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}