
rule TrojanDownloader_Win32_Injector_C{
	meta:
		description = "TrojanDownloader:Win32/Injector.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {50 b8 fa 0f 00 00 e8 90 01 02 ff ff 50 53 e8 90 01 02 ff ff 68 01 02 00 00 90 00 } //01 00 
		$a_00_1 = {69 65 78 69 67 75 62 2e 73 79 73 } //01 00  iexigub.sys
		$a_00_2 = {4d 73 79 6a 68 78 75 63 2e 65 78 65 } //01 00  Msyjhxuc.exe
		$a_00_3 = {4d 73 68 75 63 78 2e 65 78 65 } //00 00  Mshucx.exe
	condition:
		any of ($a_*)
 
}