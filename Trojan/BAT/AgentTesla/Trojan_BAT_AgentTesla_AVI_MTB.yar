
rule Trojan_BAT_AgentTesla_AVI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AVI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_02_0 = {25 16 03 a2 25 0d 14 14 17 8d ?? ?? ?? 01 25 16 17 9c 25 13 ?? 28 ?? ?? ?? 0a 11 ?? 16 91 2d ?? 2b ?? 09 16 9a } //10
		$a_80_1 = {47 65 74 54 79 70 65 } //GetType  1
		$a_80_2 = {47 65 74 50 69 78 65 6c } //GetPixel  1
		$a_80_3 = {54 6f 57 69 6e 33 32 } //ToWin32  1
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=13
 
}