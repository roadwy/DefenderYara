
rule TrojanSpy_Win32_Seryce_A{
	meta:
		description = "TrojanSpy:Win32/Seryce.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {99 b9 e8 03 00 00 f7 f9 42 52 ff d3 46 83 fe 08 } //4
		$a_03_1 = {6a 06 6a 01 6a 02 ff 15 90 01 03 00 8b f0 83 fe ff 74 db b8 02 00 00 00 6a 50 90 00 } //2
		$a_01_2 = {5f 61 62 72 6f 61 64 } //1 _abroad
		$a_01_3 = {5f 63 68 69 6e 61 } //1 _china
		$a_01_4 = {21 77 69 6e 37 } //1 !win7
		$a_01_5 = {67 6f 74 6f 77 69 6e 2e 45 6e 63 72 79 70 74 44 65 63 72 79 70 74 2e 53 69 6d 70 6c 65 } //1 gotowin.EncryptDecrypt.Simple
		$a_01_6 = {48 6f 73 74 49 44 3d 25 73 26 56 65 72 73 69 6f 6e 3d 25 73 26 4f 53 3d 25 73 26 69 70 3d 25 73 } //1 HostID=%s&Version=%s&OS=%s&ip=%s
	condition:
		((#a_01_0  & 1)*4+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}