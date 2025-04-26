
rule PWS_Win32_OnLineGames_NG{
	meta:
		description = "PWS:Win32/OnLineGames.NG,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {c7 85 6c ff ff ff 65 6c 6c 53 c7 85 70 ff ff ff 65 72 76 69 c7 85 74 ff ff ff 63 65 4f 62 c7 85 78 ff ff ff 6a 65 63 74 c7 85 7c ff ff ff 44 65 6c 61 c7 45 80 79 4c } //1
		$a_01_1 = {48 6f 6f 6b 2e 64 6c 6c } //1 Hook.dll
		$a_01_2 = {42 72 6f 61 64 63 61 73 74 53 79 73 74 65 6d 4d 65 73 73 61 67 65 41 } //1 BroadcastSystemMessageA
		$a_01_3 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //1 SetWindowsHookExA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}