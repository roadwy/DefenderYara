
rule TrojanDownloader_Win32_Stration_DJ{
	meta:
		description = "TrojanDownloader:Win32/Stration.DJ,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0b 00 06 00 00 "
		
	strings :
		$a_02_0 = {59 51 c1 e9 02 f3 a5 59 83 e1 03 f3 a4 33 ?? 0f b6 44 ?? ?? 30 04 ?? ?? 83 ?? ?? 7c } //5
		$a_00_1 = {47 45 54 20 25 73 20 48 54 54 50 2f 31 2e 31 } //1 GET %s HTTP/1.1
		$a_00_2 = {48 6f 73 74 3a 20 25 73 } //1 Host: %s
		$a_00_3 = {50 72 61 67 6d 61 3a 20 6e 6f 2d 63 61 63 68 65 } //1 Pragma: no-cache
		$a_02_4 = {43 6f 6e 74 65 6e 74 2d 4c 65 6e 67 74 68 3a [0-05] 48 54 54 50 [0-05] 32 30 30 [0-05] 34 30 34 00 } //5
		$a_00_5 = {2f 6e 74 73 72 76 33 32 2e 65 78 65 } //1 /ntsrv32.exe
	condition:
		((#a_02_0  & 1)*5+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*5+(#a_00_5  & 1)*1) >=11
 
}