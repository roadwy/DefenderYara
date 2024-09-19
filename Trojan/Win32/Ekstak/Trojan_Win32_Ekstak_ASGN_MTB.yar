
rule Trojan_Win32_Ekstak_ASGN_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASGN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {65 00 ff 15 ?? ?? 65 00 6a 00 66 ?? ?? 50 cf 65 00 7f 00 e8 ?? ?? ?? 00 01 05 ?? ?? 65 00 ff 15 ?? ?? 65 00 8b f0 81 e6 ff 00 00 00 83 fe 06 0f 93 c0 83 fe 06 a2 ?? ?? 65 00 72 5c 57 e8 } //4
		$a_03_1 = {50 ff d6 68 ?? ?? 65 00 50 ff d7 8b f0 5f 89 35 ?? ?? 65 00 68 ?? ?? 65 00 ff 15 ?? ?? 65 00 8b c6 5e c3 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*1) >=5
 
}