
rule PWS_Win32_Perfwo_B{
	meta:
		description = "PWS:Win32/Perfwo.B,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_00_0 = {64 ff 32 64 89 22 33 c0 89 45 e8 8d 45 e8 50 8b 45 f4 } //1
		$a_00_1 = {b0 01 5b c3 00 00 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 00 00 00 43 72 65 61 74 65 54 6f 6f 6c } //1
		$a_01_2 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_3 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //1 CreateRemoteThread
		$a_00_4 = {64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //1 drivers\etc\hosts
		$a_00_5 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e } //1 CurrentVersion\Winlogon
		$a_00_6 = {24 24 74 6d 70 2e 62 61 74 } //1 $$tmp.bat
		$a_00_7 = {63 6c 69 65 6e 74 2e 65 78 65 } //1 client.exe
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=8
 
}