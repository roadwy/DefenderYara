
rule TrojanDownloader_Win32_Injector_C{
	meta:
		description = "TrojanDownloader:Win32/Injector.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {50 b8 fa 0f 00 00 e8 ?? ?? ff ff 50 53 e8 ?? ?? ff ff 68 01 02 00 00 } //1
		$a_00_1 = {69 65 78 69 67 75 62 2e 73 79 73 } //1 iexigub.sys
		$a_00_2 = {4d 73 79 6a 68 78 75 63 2e 65 78 65 } //1 Msyjhxuc.exe
		$a_00_3 = {4d 73 68 75 63 78 2e 65 78 65 } //1 Mshucx.exe
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}