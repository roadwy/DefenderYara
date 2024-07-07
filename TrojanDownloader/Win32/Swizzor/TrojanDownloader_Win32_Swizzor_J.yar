
rule TrojanDownloader_Win32_Swizzor_J{
	meta:
		description = "TrojanDownloader:Win32/Swizzor.J,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_00_0 = {e8 00 00 00 00 b8 6f 83 00 00 5b 03 c3 ff e0 } //10
		$a_02_1 = {8a 17 32 14 18 88 17 40 83 f8 90 01 01 7c 02 90 00 } //10
	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}