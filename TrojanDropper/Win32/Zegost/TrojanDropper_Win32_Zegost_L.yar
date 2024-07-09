
rule TrojanDropper_Win32_Zegost_L{
	meta:
		description = "TrojanDropper:Win32/Zegost.L,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_03_0 = {33 c0 b1 11 8a 90 90 ?? ?? ?? ?? 32 d1 88 90 90 ?? ?? ?? ?? 40 3d 00 ?? 02 00 7c ea } //5
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 76 63 68 6f 73 74 } //1 SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost
		$a_01_2 = {5c 50 61 72 61 6d 65 74 65 72 73 } //1 \Parameters
		$a_01_3 = {63 6d 64 2e 65 78 65 20 2f 63 20 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 20 68 69 } //1 cmd.exe /c rundll32.exe %s hi
		$a_00_4 = {49 6e 73 74 61 6c 6c 4d 6f 64 75 6c 65 } //1 InstallModule
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1) >=7
 
}