
rule Trojan_Win32_Acbot_A{
	meta:
		description = "Trojan:Win32/Acbot.A,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 07 00 00 "
		
	strings :
		$a_01_0 = {81 e1 00 20 00 00 74 24 8b 95 ec f7 ff ff 0f b6 02 83 e0 38 75 0c c7 85 f0 f7 ff ff 00 18 00 00 eb 0a } //2
		$a_03_1 = {68 e9 00 00 00 8b 45 0c 50 e8 90 01 04 83 c4 08 8b 4d 08 2b 4d 0c 83 e9 05 51 8b 55 0c 83 c2 01 52 e8 90 01 04 83 c4 08 5d c3 90 00 } //2
		$a_01_2 = {6d 73 67 5f 69 64 3d 25 73 26 63 6c 69 65 6e 74 5f 74 69 6d 65 3d 25 73 26 74 6f 3d 25 73 26 6d 73 67 5f 74 65 78 74 3d 25 73 26 63 6f 6e 66 69 72 6d 65 64 3d 31 26 63 61 70 74 63 68 61 5f 70 65 } //2 msg_id=%s&client_time=%s&to=%s&msg_text=%s&confirmed=1&captcha_pe
		$a_01_3 = {50 52 4f 43 4d 4f 4e 5f 57 49 4e 44 4f 57 5f 43 4c 41 53 53 } //1 PROCMON_WINDOW_CLASS
		$a_01_4 = {2a 49 45 58 50 4c 4f 52 45 2e 45 58 45 } //1 *IEXPLORE.EXE
		$a_01_5 = {57 65 62 4b 69 74 32 57 65 62 50 72 6f 63 65 73 73 } //1 WebKit2WebProcess
		$a_01_6 = {4f 72 64 65 72 65 64 46 72 69 65 6e 64 73 4c 69 73 74 2e 69 6e 69 74 } //1 OrderedFriendsList.init
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=9
 
}