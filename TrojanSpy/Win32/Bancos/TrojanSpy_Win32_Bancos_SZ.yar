
rule TrojanSpy_Win32_Bancos_SZ{
	meta:
		description = "TrojanSpy:Win32/Bancos.SZ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {52 43 50 54 20 54 4f 3a 3c 00 } //1 䍒呐吠㩏<
		$a_01_1 = {61 79 75 64 6d 73 6a 68 72 77 6c 6f 70 68 67 66 76 72 63 64 65 73 61 69 6d 6c 6b 68 67 64 77 78 75 70 6f 79 72 76 74 61 64 73 6b 6c 6f 69 75 72 71 6e 00 } //1
		$a_03_2 = {0f b6 44 38 ff 89 45 90 01 01 b8 90 01 04 0f b6 44 18 ff 89 45 90 01 01 8d 45 90 01 01 8b 55 90 01 01 2b 55 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}