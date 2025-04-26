
rule Trojan_BAT_AgentTesla_ABJK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 72 ?? ?? ?? 70 a2 25 17 72 ?? ?? ?? 70 a2 14 14 14 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0b 07 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 0c 90 0a 3b 00 7e ?? ?? ?? 04 14 72 ?? ?? ?? 70 18 8d } //2
		$a_03_1 = {0a 0a 2b 00 06 2a 90 0a 10 00 02 28 ?? ?? ?? 0a 28 } //2
		$a_01_2 = {50 00 65 00 72 00 70 00 75 00 73 00 74 00 61 00 6b 00 61 00 61 00 6e 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 Perpustakaan.Resources
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}