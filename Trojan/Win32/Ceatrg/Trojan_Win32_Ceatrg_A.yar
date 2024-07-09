
rule Trojan_Win32_Ceatrg_A{
	meta:
		description = "Trojan:Win32/Ceatrg.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 46 7c 00 ff ff ff ff 06 00 00 00 46 6c 6f 6f 64 5b 00 } //1
		$a_03_1 = {6a 00 68 01 20 00 00 56 8b 43 04 50 e8 ?? ?? ?? ?? 85 c0 7e 03 40 75 ?? 8b 43 04 50 e8 ?? ?? ?? ?? 68 88 13 00 00 e8 ?? ?? ?? ?? e9 ?? ?? ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}