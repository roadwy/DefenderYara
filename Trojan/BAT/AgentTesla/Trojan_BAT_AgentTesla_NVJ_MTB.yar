
rule Trojan_BAT_AgentTesla_NVJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NVJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {57 3f b6 3f 09 0f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 9f 00 00 00 5c 00 00 00 7f 02 00 00 c8 02 00 00 29 02 00 00 25 00 00 00 4c 01 00 00 39 } //1
		$a_01_1 = {53 61 6e 66 6f 72 64 2e 4d 75 6c 74 69 6d 65 64 69 61 2e 4d 69 64 69 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 Sanford.Multimedia.Midi.Properties.Resources
		$a_01_2 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_01_3 = {43 6f 6c 6f 72 54 72 61 6e 73 6c 61 74 6f 72 } //1 ColorTranslator
		$a_01_4 = {54 6f 57 69 6e 33 32 } //1 ToWin32
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}