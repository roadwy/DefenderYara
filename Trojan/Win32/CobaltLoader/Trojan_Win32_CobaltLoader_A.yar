
rule Trojan_Win32_CobaltLoader_A{
	meta:
		description = "Trojan:Win32/CobaltLoader.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {6f 70 65 72 61 5f 62 72 6f 77 73 65 72 2e 64 6c 6c 00 } //2
		$a_01_1 = {6f 70 65 72 61 5f 62 72 6f 77 73 65 72 2e 70 6e 67 00 } //2
		$a_03_2 = {33 c9 c7 85 e4 fd ff ff ?? ?? ?? ?? 85 f6 7e 1c 0f 1f 84 00 00 00 00 00 8b c1 83 e0 03 8a 84 05 e4 fd ff ff 30 04 39 41 3b ce } //3
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*3) >=7
 
}