
rule Trojan_Win32_Nymaim_NI_MTB{
	meta:
		description = "Trojan:Win32/Nymaim.NI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 e0 04 8b 44 01 ?? 89 44 24 50 8b 44 24 ?? 8b 4c 24 30 89 8c 24 ?? ?? ?? ?? 8b 54 24 2c } //3
		$a_03_1 = {0f b7 b4 24 ?? ?? ?? ?? 01 f6 66 89 f7 66 89 bc 24 ?? ?? ?? ?? 89 44 24 54 8b 74 24 50 31 c6 } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}