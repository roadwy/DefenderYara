
rule Trojan_Win32_Killav_FV{
	meta:
		description = "Trojan:Win32/Killav.FV,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_02_0 = {8d 85 38 ff ff ff ba 12 00 00 00 e8 ?? ?? ?? ?? 8b 85 38 ff ff ff e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 83 f8 01 1b c0 40 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 84 c0 74 0a b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 84 c0 74 0a b8 } //1
		$a_03_1 = {50 6a 00 68 3f 00 0f 00 6a 00 6a 00 6a 00 68 ?? ?? ?? ?? 68 ?? 00 00 80 e8 ?? ?? ?? ?? 85 c0 75 ?? 8b 5d fc 85 db 74 ?? 83 eb 04 8b 1b 43 53 8b 45 fc e8 ?? ?? ?? ?? 50 6a 01 6a 00 8b 45 f8 } //1
		$a_00_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_00_3 = {41 56 47 49 44 53 41 67 65 6e 74 2e 65 78 65 } //1 AVGIDSAgent.exe
		$a_00_4 = {41 56 47 49 44 53 4d 6f 6e 69 74 6f 72 2e 65 78 65 } //1 AVGIDSMonitor.exe
	condition:
		((#a_02_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}