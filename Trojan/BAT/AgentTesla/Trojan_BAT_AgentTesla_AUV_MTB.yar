
rule Trojan_BAT_AgentTesla_AUV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AUV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_80_0 = {65 70 79 54 74 65 47 } //epyTteG  1
		$a_80_1 = {47 65 74 4d 65 74 68 6f 64 } //GetMethod  1
		$a_80_2 = {49 44 4d 2e 49 55 65 6c 70 6d 69 53 } //IDM.IUelpmiS  1
		$a_80_3 = {49 6e 76 6f 6b 65 } //Invoke  1
		$a_80_4 = {54 6f 43 68 61 72 41 72 72 61 79 } //ToCharArray  1
		$a_80_5 = {47 65 74 50 69 78 65 6c } //GetPixel  1
		$a_80_6 = {54 6f 57 69 6e 33 32 } //ToWin32  1
		$a_80_7 = {52 65 73 6f 75 72 63 65 4d 61 6e 61 67 65 72 } //ResourceManager  1
		$a_80_8 = {53 65 6c 65 63 74 6f 72 58 } //SelectorX  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1) >=9
 
}