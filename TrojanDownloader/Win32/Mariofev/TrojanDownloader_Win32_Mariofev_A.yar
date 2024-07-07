
rule TrojanDownloader_Win32_Mariofev_A{
	meta:
		description = "TrojanDownloader:Win32/Mariofev.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {26 78 36 34 3d } //1 &x64=
		$a_00_1 = {26 75 61 63 3d } //1 &uac=
		$a_01_2 = {6a 03 ff 75 f8 ff d7 85 c0 74 09 83 3b 0c 73 04 } //1
		$a_01_3 = {89 44 24 28 ff 54 24 38 33 f6 bf c8 00 00 00 ff d5 3b 44 24 10 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}