
rule TrojanDownloader_Win32_Renos_FZ{
	meta:
		description = "TrojanDownloader:Win32/Renos.FZ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {8d 51 10 33 c0 89 02 89 42 04 c7 01 01 23 45 67 c7 41 04 89 ab cd ef c7 41 08 fe dc ba 98 c7 41 0c 76 54 32 10 } //1
		$a_02_1 = {3a 2f 2f 64 6f 77 6e 6c 6f 61 64 2d 62 61 73 65 2e 63 6f 6d 2f [0-10] 2f [0-10] 2e 70 68 70 3f 64 61 74 61 3d } //1
		$a_01_2 = {53 6e 6d 70 55 74 69 6c 4f 69 64 43 70 79 } //1 SnmpUtilOidCpy
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}