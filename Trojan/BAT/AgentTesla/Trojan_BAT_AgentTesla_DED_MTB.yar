
rule Trojan_BAT_AgentTesla_DED_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {08 06 8e 69 33 02 16 0c 07 09 02 09 91 06 07 09 91 08 61 91 59 d2 9c 08 17 58 0c 09 17 58 0d 09 02 8e 69 } //1
		$a_01_1 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //1 GetExecutingAssembly
		$a_01_2 = {47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 } //1 GetManifestResource
		$a_01_3 = {54 6f 49 6e 74 33 32 } //1 ToInt32
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}