
rule Trojan_BAT_Agentesla_RT_MTB{
	meta:
		description = "Trojan:BAT/Agentesla.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {07 09 11 04 6f 90 01 04 13 05 11 05 28 90 01 04 13 06 08 06 11 06 b4 9c 11 04 17 d6 13 04 11 04 16 31 90 00 } //1
		$a_81_1 = {54 6f 57 69 6e 33 32 } //1 ToWin32
		$a_81_2 = {47 65 74 50 69 78 65 6c } //1 GetPixel
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}