
rule Trojan_BAT_AgentTesla_RPA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {16 0b 2b 2e 02 11 05 06 07 28 e1 00 00 06 13 07 11 06 13 09 11 09 13 08 11 08 1f 17 2e 02 2b 02 2b 0c 09 08 02 11 07 28 e0 00 00 06 d2 9c 07 17 58 0b 07 17 fe 04 13 0a 11 0a 2d c8 08 17 58 0c 06 17 58 0a 06 20 00 80 00 00 fe 04 13 0b 11 0b 2d ae } //1
		$a_01_1 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_01_2 = {43 6f 6c 6f 72 54 72 61 6e 73 6c 61 74 6f 72 } //1 ColorTranslator
		$a_01_3 = {54 6f 57 69 6e 33 32 } //1 ToWin32
		$a_01_4 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
		$a_01_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}