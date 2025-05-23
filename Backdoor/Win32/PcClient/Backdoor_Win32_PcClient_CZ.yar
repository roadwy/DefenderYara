
rule Backdoor_Win32_PcClient_CZ{
	meta:
		description = "Backdoor:Win32/PcClient.CZ,SIGNATURE_TYPE_PEHSTR_EXT,20 00 20 00 0e 00 00 "
		
	strings :
		$a_00_0 = {53 59 53 54 45 4d 5c 43 6f 6e 74 72 6f 6c 53 65 74 30 30 31 5c 53 65 72 76 69 63 65 73 5c 25 73 } //1 SYSTEM\ControlSet001\Services\%s
		$a_00_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 76 63 48 6f 73 74 } //1 SOFTWARE\Microsoft\Windows NT\CurrentVersion\SvcHost
		$a_00_2 = {4e 65 74 77 6f 72 6b 20 44 44 45 } //1 Network DDE
		$a_00_3 = {5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b } //1 \svchost.exe -k
		$a_00_4 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 36 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 32 3b 20 53 56 31 3b 20 2e 4e 45 54 20 43 4c 52 20 31 2e 31 2e 34 33 32 32 29 } //1 Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; SV1; .NET CLR 1.1.4322)
		$a_00_5 = {50 63 43 6c 69 65 6e 74 2e 64 6c 6c } //1 PcClient.dll
		$a_00_6 = {4c 6f 61 64 50 72 6f 66 69 6c 65 } //1 LoadProfile
		$a_00_7 = {53 65 72 76 69 63 65 4d 61 69 6e } //1 ServiceMain
		$a_00_8 = {53 65 72 76 69 63 65 44 6c 6c } //1 ServiceDll
		$a_00_9 = {54 65 73 74 46 75 6e 63 } //1 TestFunc
		$a_00_10 = {43 61 6c 6c 4e 65 78 74 48 6f 6f 6b 45 78 } //1 CallNextHookEx
		$a_00_11 = {69 00 6d 00 61 00 67 00 65 00 2f 00 6a 00 70 00 65 00 67 00 } //1 image/jpeg
		$a_02_12 = {68 7f 03 00 00 6a 00 68 ?? ?? 00 10 ff 15 ?? ?? 00 10 85 c0 74 07 50 ff 15 ?? ?? 00 10 68 cf 01 00 40 6a 00 6a 00 68 ?? ?? 00 10 ff 15 ?? ?? 00 10 85 c0 74 07 50 ff 15 ?? ?? 00 10 68 03 00 2e 00 6a 00 68 12 03 00 00 68 ff ff 00 00 ff 15 ?? ?? 00 10 } //10
		$a_02_13 = {53 56 8b 75 0c 33 db 57 39 9e 08 02 00 00 74 0d 8d 86 00 01 00 00 50 ff 15 ?? ?? 00 10 8d 4d e4 e8 ?? ?? 00 00 8d 86 00 01 00 00 53 68 01 30 00 00 50 8d 4d e4 89 5d fc 89 45 e0 e8 ?? ?? 00 00 85 c0 0f 84 a7 00 00 00 39 9e 08 02 00 00 75 18 8d 4d e4 e8 ?? ?? 00 00 85 c0 76 0c } //10
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_02_12  & 1)*10+(#a_02_13  & 1)*10) >=32
 
}