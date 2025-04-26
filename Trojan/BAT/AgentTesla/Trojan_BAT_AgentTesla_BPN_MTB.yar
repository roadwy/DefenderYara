
rule Trojan_BAT_AgentTesla_BPN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BPN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {07 02 09 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 84 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 26 09 18 d6 16 2d } //1
		$a_02_1 = {91 08 61 07 11 07 91 61 b4 9c 11 07 03 6f ?? ?? ?? 0a 17 da 16 2d } //1
		$a_81_2 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_81_3 = {54 6f 49 6e 74 33 32 } //1 ToInt32
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}