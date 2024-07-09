
rule Trojan_Win32_Nedsym_G{
	meta:
		description = "Trojan:Win32/Nedsym.G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {75 af 6a 04 68 00 10 00 00 68 54 96 01 00 6a 00 e8 ?? ?? ?? ?? 89 45 f0 } //1
		$a_01_1 = {58 ff d0 85 c0 75 1d 8b 7d 0c 8a 07 0c 20 3c 74 75 09 c6 05 } //1
		$a_01_2 = {85 c0 75 06 8b 5c ee 6c eb 2e 43 81 fb e7 03 00 00 75 df 57 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}
rule Trojan_Win32_Nedsym_G_2{
	meta:
		description = "Trojan:Win32/Nedsym.G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {ac 84 c0 74 13 fe c2 8a ca 80 e1 1f 80 c1 61 fe ce 32 ce 32 c1 aa eb e8 } //1
		$a_01_1 = {4e 80 3e 77 75 0d 80 7e 01 77 75 07 80 7e 02 77 75 01 ad } //1
		$a_03_2 = {81 3e 52 4d 5f 51 0f 85 ?? ?? ?? ?? 81 7e 04 50 5f 45 4e 0f 85 ?? ?? ?? ?? 81 7e 08 43 4f 44 45 0f 85 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}