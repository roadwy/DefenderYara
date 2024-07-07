
rule Trojan_Win32_BHO_CL{
	meta:
		description = "Trojan:Win32/BHO.CL,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {f3 ab 66 ab aa bf 90 01 04 83 c9 ff 33 c0 68 90 01 04 f2 ae f7 d1 2b f9 68 04 01 00 00 8b c1 8b f7 8b fa 89 5c 90 01 02 c1 e9 02 f3 a5 8b c8 33 c0 83 e1 03 89 5c 90 01 02 f3 a4 8d 7c 90 01 02 83 c9 ff f2 ae f7 d1 49 51 8d 4c 90 01 02 51 e8 90 00 } //1
		$a_00_1 = {62 68 6f 32 2e 44 4c 4c } //1 bho2.DLL
		$a_00_2 = {43 4c 53 49 44 5c 25 73 5c 49 6e 70 72 6f 63 53 65 72 76 65 72 33 32 } //1 CLSID\%s\InprocServer32
		$a_01_3 = {6b 65 79 00 63 68 61 6e 6e 65 6c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}