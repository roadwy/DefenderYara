
rule Trojan_BAT_AgentTesla_AVF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AVF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_02_0 = {07 17 d6 0b 17 ?? ?? ?? ?? ?? ?? ?? 00 11 ?? 17 d6 13 ?? 1d 13 ?? 2b ?? 00 02 09 28 ?? ?? ?? 06 26 1e 13 ?? 2b ?? 00 11 ?? 28 ?? ?? ?? 0a 0a 1c 13 ?? 2b } //10
		$a_80_1 = {54 6f 57 69 6e 33 32 } //ToWin32  1
		$a_80_2 = {47 65 74 50 69 78 65 6c } //GetPixel  1
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=12
 
}