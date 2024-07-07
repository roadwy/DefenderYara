
rule Adware_Win32_Qjwmonkey_Z{
	meta:
		description = "Adware:Win32/Qjwmonkey.Z,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4f 75 74 70 75 74 5c 52 65 6c 65 61 73 65 5c 42 5a 44 6f 77 6e 6c 6f 61 64 2e 70 64 62 } //1 Output\Release\BZDownload.pdb
		$a_01_1 = {71 00 71 00 70 00 63 00 74 00 72 00 61 00 79 00 2e 00 65 00 78 00 65 00 } //1 qqpctray.exe
		$a_01_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 63 00 64 00 6e 00 2e 00 7a 00 72 00 79 00 39 00 37 00 2e 00 63 00 6f 00 6d 00 } //1 http://cdn.zry97.com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}