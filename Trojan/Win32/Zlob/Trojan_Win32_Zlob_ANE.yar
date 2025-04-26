
rule Trojan_Win32_Zlob_ANE{
	meta:
		description = "Trojan:Win32/Zlob.ANE,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {66 7f 18 8b ?? 08 0f be ?? 83 f8 61 7c 0d 8b ?? 08 0f be ?? 83 e8 60 eb 04 } //2
		$a_03_1 = {00 52 6a 01 8d 4d ?? e8 ?? ?? ?? ?? 8b 45 ?? 83 c0 05 89 45 90 09 20 00 [0-20] 0f b7 55 ?? 81 f2 } //2
		$a_03_2 = {d1 e0 50 8b 4d ?? 51 ba 08 00 00 00 d1 e2 52 8b 45 ?? 50 e8 } //1
		$a_01_3 = {42 68 6f 4e 65 77 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}