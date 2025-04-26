
rule TrojanDownloader_Win32_Meb_A{
	meta:
		description = "TrojanDownloader:Win32/Meb.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {6a 11 59 e8 aa 02 00 00 90 e2 f8 68 6f 6e 00 00 68 75 72 6c 6d } //1
		$a_00_1 = {6a 01 59 e8 79 02 00 00 e2 f9 68 6c 33 32 00 68 73 68 65 6c } //1
		$a_02_2 = {c7 04 03 5c ?? 2e 65 c7 44 03 04 78 65 00 00 } //1
		$a_00_3 = {5b c6 07 b8 89 5f 01 66 c7 47 05 ff e0 c3 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}