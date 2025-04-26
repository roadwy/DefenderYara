
rule Trojan_BAT_AgentTesla_NTK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NTK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {02 05 04 5d 91 03 05 1f 16 5d 6f ?? ?? ?? 0a 61 } //1
		$a_01_1 = {06 03 04 17 58 20 } //1 ̆ᜄ⁘
		$a_01_2 = {06 03 04 17 58 20 00 3e 00 00 5d 91 28 } //1
		$a_01_3 = {5d 03 02 20 00 3e 00 00 04 28 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}