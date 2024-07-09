
rule Trojan_Win32_LokiBot_DFA_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.DFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c7 44 24 28 00 00 00 00 f7 f1 0f b6 0d ?? ?? ?? ?? 0f af c1 8b 0d ?? ?? ?? ?? 0f af 0d cc 24 4a 00 03 c1 0f b7 0d ?? ?? ?? ?? 2b c1 2b 05 a4 2a 4a 00 40 a3 14 27 4a } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}