
rule Backdoor_Win32_PcClient_DI{
	meta:
		description = "Backdoor:Win32/PcClient.DI,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 02 00 "
		
	strings :
		$a_01_0 = {c6 85 14 fb ff ff 70 c6 85 15 fb ff ff 61 c6 85 16 fb ff ff 73 c6 85 17 fb ff ff 73 } //02 00 
		$a_01_1 = {c6 85 85 fe ff ff 78 c6 85 86 fe ff ff 2e c6 85 87 fe ff ff 69 c6 85 88 fe ff ff 6e c6 85 89 fe ff ff 69 } //03 00 
		$a_02_2 = {6d 79 70 61 72 65 6e 74 74 68 72 65 61 64 69 64 3d 25 64 3b 90 01 04 69 64 3d 25 73 90 00 } //02 00 
		$a_02_3 = {47 6c 6f 62 61 6c 5c 25 73 2d 90 01 03 2d 6d 65 74 75 78 90 00 } //02 00 
		$a_02_4 = {47 6c 6f 62 61 6c 5c 25 73 2d 90 01 03 2d 65 76 65 6e 74 90 00 } //01 00 
		$a_00_5 = {6d 79 74 68 72 65 61 64 69 64 } //01 00  mythreadid
		$a_00_6 = {25 64 25 64 2e 65 78 65 } //01 00  %d%d.exe
		$a_00_7 = {5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b } //01 00  \svchost.exe -k
		$a_00_8 = {5b 25 30 32 64 2d 25 30 34 64 2d 25 30 32 64 20 25 30 32 64 3a 25 30 32 64 3a 25 30 32 64 5d } //01 00  [%02d-%04d-%02d %02d:%02d:%02d]
		$a_00_9 = {50 4f 53 54 20 2f 25 73 20 48 54 54 50 2f 31 2e 31 } //00 00  POST /%s HTTP/1.1
	condition:
		any of ($a_*)
 
}