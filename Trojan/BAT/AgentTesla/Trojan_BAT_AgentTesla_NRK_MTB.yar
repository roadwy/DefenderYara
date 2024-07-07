
rule Trojan_BAT_AgentTesla_NRK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NRK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_03_0 = {20 00 aa 02 00 8c 90 01 01 00 00 01 16 28 7d 00 00 0a 13 05 90 01 01 13 0b 2b 93 11 05 2c 05 90 01 01 13 0b 2b 8a 90 00 } //1
		$a_01_1 = {47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 53 74 72 65 61 6d } //1 GetManifestResourceStream
		$a_80_2 = {47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 4e 61 6d 65 73 } //GetManifestResourceNames  1
		$a_01_3 = {47 65 74 4f 62 6a 65 63 74 56 61 6c 75 65 } //1 GetObjectValue
		$a_01_4 = {54 6f 49 6e 74 65 67 65 72 } //1 ToInteger
		$a_01_5 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //1 GetTypeFromHandle
		$a_01_6 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_80_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}