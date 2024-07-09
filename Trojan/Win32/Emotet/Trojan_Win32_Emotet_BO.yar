
rule Trojan_Win32_Emotet_BO{
	meta:
		description = "Trojan:Win32/Emotet.BO,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_00_0 = {68 65 23 40 31 2e 50 64 62 } //1 he#@1.Pdb
		$a_03_1 = {8b 44 24 18 89 c1 83 e0 ?? 8a ?? ?? ?? ?? ?? c7 44 24 ?? ?? ?? ?? ?? c7 44 24 ?? ?? ?? ?? ?? 8b 44 24 ?? 8a 34 08 28 d6 8b 74 24 ?? 88 34 0e 83 c1 ?? 89 4c 24 ?? 8b 7c 24 ?? 39 f9 74 } //3
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*3) >=4
 
}