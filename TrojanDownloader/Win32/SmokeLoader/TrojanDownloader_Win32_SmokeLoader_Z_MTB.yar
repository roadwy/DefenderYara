
rule TrojanDownloader_Win32_SmokeLoader_Z_MTB{
	meta:
		description = "TrojanDownloader:Win32/SmokeLoader.Z!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {b8 18 00 00 00 6b c8 00 8b 54 0d dc 83 c2 30 b8 01 00 00 00 6b c8 11 8b 45 08 88 14 08 } //1
		$a_01_1 = {68 b8 33 41 00 ff 15 30 30 41 00 89 45 fc } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}