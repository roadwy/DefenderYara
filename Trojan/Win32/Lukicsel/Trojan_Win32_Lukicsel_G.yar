
rule Trojan_Win32_Lukicsel_G{
	meta:
		description = "Trojan:Win32/Lukicsel.G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {57 69 6e 6c 6f 67 6f 6e 4c 6f 67 6f 66 66 45 76 00 57 69 6e 6c 6f 67 6f 6e 53 74 61 72 74 75 70 45 76 00 } //1
		$a_01_1 = {8e 5e 40 fd 6c 6d 6a 47 1e e0 a7 8f e9 2d b7 00 00 00 00 00 } //1
		$a_03_2 = {8d 45 08 e8 ?? ?? ?? ?? 32 06 88 07 46 47 4b 75 ef } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*2) >=3
 
}