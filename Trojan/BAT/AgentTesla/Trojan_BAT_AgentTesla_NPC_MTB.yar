
rule Trojan_BAT_AgentTesla_NPC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {07 16 fe 02 16 fe 01 0c 08 2c 17 07 17 d6 0b 06 20 90 01 03 00 8c 90 01 03 01 6f 90 01 03 0a 00 2b dd 90 00 } //1
		$a_80_1 = {47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 4e 61 6d 65 73 } //GetManifestResourceNames  1
		$a_01_2 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //1 GetTypeFromHandle
		$a_01_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_4 = {54 6f 49 6e 74 65 67 65 72 } //1 ToInteger
	condition:
		((#a_03_0  & 1)*1+(#a_80_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}