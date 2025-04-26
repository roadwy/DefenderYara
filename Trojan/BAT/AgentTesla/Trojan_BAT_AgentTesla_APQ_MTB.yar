
rule Trojan_BAT_AgentTesla_APQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.APQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_03_0 = {07 11 04 11 07 ?? ?? ?? ?? ?? 13 08 11 08 ?? ?? ?? ?? ?? 13 09 08 06 11 09 b4 9c 11 07 17 d6 13 07 11 07 11 06 31 d9 } //10
		$a_81_1 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_81_2 = {54 6f 57 69 6e 33 32 } //1 ToWin32
		$a_81_3 = {53 69 6d 70 6c 65 55 49 2e 4d 44 49 } //1 SimpleUI.MDI
	condition:
		((#a_03_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=13
 
}