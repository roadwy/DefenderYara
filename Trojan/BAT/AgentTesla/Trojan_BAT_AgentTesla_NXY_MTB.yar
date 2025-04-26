
rule Trojan_BAT_AgentTesla_NXY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NXY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {0a 13 08 12 08 28 ?? 00 00 0a 28 ?? 00 00 0a 16 09 06 1a 28 ?? 00 00 0a 00 06 1a 58 0a 16 2d cb 00 11 07 17 58 16 2d } //1
		$a_01_1 = {42 69 74 43 6f 6e 76 65 72 74 65 72 } //1 BitConverter
		$a_01_2 = {54 6f 49 6e 74 33 32 } //1 ToInt32
		$a_01_3 = {4b 65 79 73 4e 6f 72 6d 61 6c 69 7a 65 2e 64 } //1 KeysNormalize.d
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}