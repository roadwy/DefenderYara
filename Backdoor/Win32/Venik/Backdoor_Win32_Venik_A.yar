
rule Backdoor_Win32_Venik_A{
	meta:
		description = "Backdoor:Win32/Venik.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_03_0 = {6a 0c 50 68 04 00 00 98 57 c7 44 ?? 2c 01 00 00 00 c7 44 24 ?? e8 03 00 00 ff 15 } //1
		$a_03_1 = {b9 fe 00 00 00 25 ff 00 00 00 56 99 f7 f9 8b 74 24 ?? fe c2 85 f6 76 ?? 8b 44 24 ?? 8a 08 32 ca 02 ca 88 08 } //1
		$a_03_2 = {2e 50 41 58 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 50 41 44 ?? ?? ?? ?? 52 65 67 53 65 74 56 61 6c 75 65 45 78 28 53 65 72 76 69 63 65 44 6c 6c 29 } //1
		$a_01_3 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 53 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 6b 72 6e 6c 73 72 76 63 } //1 %SystemRoot%\System32\svchost.exe -k krnlsrvc
		$a_01_4 = {50 72 6f 76 69 64 65 73 20 73 75 70 70 6f 72 74 20 66 6f 72 20 6d 65 64 69 61 20 70 61 6c 79 65 72 2e 20 54 68 69 73 20 73 65 72 76 69 63 65 20 63 61 6e 27 74 20 62 65 20 73 74 6f 70 65 64 2e } //1 Provides support for media palyer. This service can't be stoped.
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}