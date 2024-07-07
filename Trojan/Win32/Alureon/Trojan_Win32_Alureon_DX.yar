
rule Trojan_Win32_Alureon_DX{
	meta:
		description = "Trojan:Win32/Alureon.DX,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {eb 16 8b 16 ff 4d 0c 8d 74 16 04 3b f0 72 27 8b 55 08 03 d0 3b f2 73 1e } //2
		$a_01_1 = {8b f8 b8 00 20 00 00 66 09 47 16 } //2
		$a_01_2 = {6c 64 72 31 36 00 } //1 摬ㅲ6
		$a_01_3 = {62 63 6b 66 67 2e 74 6d 70 00 } //1
		$a_01_4 = {73 72 76 00 63 6d 64 00 77 73 72 76 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}