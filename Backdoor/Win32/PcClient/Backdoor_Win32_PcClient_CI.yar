
rule Backdoor_Win32_PcClient_CI{
	meta:
		description = "Backdoor:Win32/PcClient.CI,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_02_0 = {f3 ab 6a 02 6a 00 6a d0 ff b5 b8 fe ff ff ff 15 90 01 02 40 00 83 65 ec 00 6a 00 8d 45 ec 50 6a 30 8d 85 bc fe ff ff 50 ff b5 b8 fe ff ff ff 15 90 01 02 40 00 6a 30 8d 85 bc fe ff ff 50 e8 68 90 01 02 00 59 59 8b 45 08 8b 8d c4 fe ff ff 89 08 8b 45 08 8b 8d c8 fe ff ff 89 48 04 8b 45 08 8b 8d cc fe ff ff 89 48 08 8b 45 08 8b 8d d0 fe ff ff 89 48 0c 8b 45 08 8b 8d d4 fe ff ff 89 48 10 0f b7 85 e0 fe ff ff 0f b7 8d da fe ff ff 03 c1 0f b7 8d d8 fe ff ff 03 c1 0f b7 8d dc fe ff ff 03 c1 0f b7 8d e4 fe ff ff 03 c1 0f b7 8d e2 fe ff ff 03 c1 0f b7 8d de fe ff ff 03 c1 0f b7 8d e6 fe ff ff 03 c1 0f b7 8d e8 fe ff ff 90 00 } //1
		$a_02_1 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 90 01 08 2e 64 6c 6c 90 00 } //1
		$a_02_2 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 64 72 69 76 65 72 73 5c 90 01 08 2e 73 79 73 90 00 } //1
		$a_02_3 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 90 01 08 2e 64 72 76 90 00 } //1
		$a_00_4 = {73 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 76 63 48 6f 73 74 } //1 software\Microsoft\Windows NT\CurrentVersion\SvcHost
		$a_00_5 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 36 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 32 3b 20 53 56 31 3b 20 2e 4e 45 54 20 43 4c 52 20 31 2e 31 2e 34 33 32 32 29 } //1 Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; SV1; .NET CLR 1.1.4322)
		$a_00_6 = {50 63 4d 61 69 6e 2e 64 6c 6c } //1 PcMain.dll
		$a_00_7 = {4c 6f 61 64 50 72 6f 66 69 6c 65 } //1 LoadProfile
		$a_00_8 = {53 65 72 76 69 63 65 4d 61 69 6e } //1 ServiceMain
		$a_00_9 = {53 65 72 76 69 63 65 44 6c 6c } //1 ServiceDll
		$a_00_10 = {5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 } //1 \svchost.exe -k 
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1) >=11
 
}