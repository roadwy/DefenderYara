
rule Trojan_Win32_Killav_DP{
	meta:
		description = "Trojan:Win32/Killav.DP,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 09 00 00 "
		
	strings :
		$a_03_0 = {00 61 6e 74 69 5f 61 76 90 0f 01 00 2e 64 6c 6c 00 } //2
		$a_03_1 = {66 c7 45 ea 0f 04 66 89 7d e8 e8 ?? ?? ?? ?? 6a 32 ff 15 ?? ?? ?? ?? 6a 1c 8d 45 e4 6a 00 50 e8 ?? ?? ?? ?? 83 4d ec 02 83 c4 0c 6a 1c 8d 45 e4 50 56 89 75 e4 66 c7 45 ea 0f 04 } //2
		$a_03_2 = {00 10 6a 09 e8 ?? ?? ?? ?? 6a 09 e8 ?? ?? ?? ?? 6a 09 e8 ?? ?? ?? ?? 6a 0d e8 } //2
		$a_01_3 = {00 7a 6f 6e 65 61 6c 61 72 6d 00 00 00 7a 61 75 6e 69 6e 73 74 2e 65 78 65 00 } //1
		$a_01_4 = {00 62 69 74 64 65 66 65 6e 64 65 72 00 6b 61 73 70 65 72 73 6b 79 00 00 00 63 70 65 73 00 } //1
		$a_01_5 = {00 61 76 67 00 6d 73 69 65 78 65 63 00 67 20 64 61 74 61 00 } //1 愀杶洀楳硥捥最搠瑡a
		$a_01_6 = {00 61 76 61 73 74 00 00 00 5c 53 65 74 75 70 5c 73 65 74 69 66 61 63 65 2e 64 6c 6c 22 2c 52 75 6e 53 65 74 75 70 00 } //1
		$a_01_7 = {00 70 6f 73 74 69 6e 73 74 61 6c 6c 00 2f 74 55 6e 49 6e 73 74 61 6c 6c 00 66 2d 73 65 63 75 72 65 00 } //1 瀀獯楴獮慴汬⼀啴䥮獮慴汬昀猭捥牵e
		$a_01_8 = {00 6d 63 61 66 65 65 00 00 6d 63 75 6e 69 6e 73 74 2e 65 78 65 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=7
 
}