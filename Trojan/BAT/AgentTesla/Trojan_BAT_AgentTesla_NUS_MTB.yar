
rule Trojan_BAT_AgentTesla_NUS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NUS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {09 11 0c 17 da 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 11 04 11 0c 11 04 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 da 13 0d 11 05 11 0d 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 05 11 0c 17 d6 13 0c 11 0c 11 0b 31 b7 } //1
		$a_01_1 = {86 06 2d 00 86 06 2d 00 86 06 2d 00 86 06 2d } //1
		$a_01_2 = {50 00 72 00 6f 00 67 00 44 00 72 00 61 00 77 00 } //1 ProgDraw
		$a_01_3 = {42 00 75 00 6e 00 69 00 66 00 75 00 5f 00 54 00 65 00 78 00 74 00 42 00 6f 00 78 00 } //1 Bunifu_TextBox
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}