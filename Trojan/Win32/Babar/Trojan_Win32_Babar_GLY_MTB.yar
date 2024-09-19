
rule Trojan_Win32_Babar_GLY_MTB{
	meta:
		description = "Trojan:Win32/Babar.GLY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {54 93 41 00 b2 ?? ?? ?? ?? 94 41 00 a1 ?? ?? ?? ?? 94 41 00 c4 94 41 00 14 95 ?? ?? ?? ?? 41 00 19 94 41 00 e3 94 41 00 50 95 41 } //10
		$a_01_1 = {74 6d 70 64 62 2e 68 6f 73 74 2e 6c 67 32 30 33 30 } //1 tmpdb.host.lg2030
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}