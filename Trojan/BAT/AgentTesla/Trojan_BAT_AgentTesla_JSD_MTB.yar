
rule Trojan_BAT_AgentTesla_JSD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JSD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 06 16 73 90 01 03 0a 73 90 01 03 0a 0c 08 07 6f 90 01 03 0a 07 6f 90 01 03 0a 0d de 1e 90 00 } //1
		$a_01_1 = {44 65 63 6f 64 65 72 } //1 Decoder
		$a_01_2 = {57 69 6e 41 70 69 } //1 WinApi
		$a_01_3 = {44 79 6e 61 6d 69 63 49 6e 76 6f 6b 65 } //1 DynamicInvoke
		$a_01_4 = {50 68 6f 6e 65 } //1 Phone
		$a_01_5 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_6 = {43 72 65 61 74 65 44 65 6c 65 67 61 74 65 } //1 CreateDelegate
		$a_01_7 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}