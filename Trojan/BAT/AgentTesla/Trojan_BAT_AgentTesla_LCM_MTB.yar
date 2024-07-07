
rule Trojan_BAT_AgentTesla_LCM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LCM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {07 11 07 11 09 6f 90 01 03 0a 13 0a 11 0a 16 16 16 16 28 90 01 03 0a 28 90 01 03 0a 13 0b 11 0b 2c 2c 00 08 12 0a 28 90 01 03 0a 6f 90 01 03 0a 00 08 12 0a 28 90 01 03 0a 6f 90 01 03 0a 00 08 12 0a 28 90 01 03 0a 6f 90 01 03 0a 00 00 00 11 09 17 d6 13 09 11 09 11 08 fe 02 16 fe 01 13 0c 11 0c 2d 90 00 } //1
		$a_01_1 = {54 6f 57 69 6e 33 32 } //1 ToWin32
		$a_01_2 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_01_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}