
rule TrojanDownloader_Win32_Rovnix_A{
	meta:
		description = "TrojanDownloader:Win32/Rovnix.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {73 19 0f be 55 10 8b 45 08 03 45 fc 0f be 08 33 ca 8b 55 08 03 55 fc 88 0a eb d6 } //01 00 
		$a_00_1 = {5c 00 5c 00 2e 00 5c 00 70 00 69 00 70 00 65 00 5c 00 76 00 68 00 6f 00 73 00 74 00 25 00 75 00 } //01 00  \\.\pipe\vhost%u
		$a_00_2 = {42 4f 4f 54 4b 49 54 5f 44 4c 4c 2e 64 6c 6c } //00 00  BOOTKIT_DLL.dll
	condition:
		any of ($a_*)
 
}