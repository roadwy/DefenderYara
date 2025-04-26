
rule Trojan_Win32_Bredo_PA_MTB{
	meta:
		description = "Trojan:Win32/Bredo.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c2 10 00 b9 ?? ?? ?? ?? 33 c0 8a 90 90 ?? ?? ?? ?? 32 d1 41 81 e1 ff 00 00 80 88 54 04 ?? 79 ?? 49 81 c9 00 ff ff ff 41 40 83 f8 ?? 7c } //1
		$a_00_1 = {68 00 61 00 68 00 61 00 68 00 61 00 2e 00 65 00 78 00 65 00 } //1 hahaha.exe
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}