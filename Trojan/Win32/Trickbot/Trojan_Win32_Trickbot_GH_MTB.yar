
rule Trojan_Win32_Trickbot_GH_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {f7 e9 c1 fa 90 01 01 8b c2 c1 e8 90 01 01 03 c2 90 02 0a 8a 90 01 02 30 90 01 01 31 41 3b cf 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Trickbot_GH_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 d2 09 fa 88 16 c7 45 b0 8b 00 00 00 8b bd 30 ff ff ff 8a 17 0f b6 d2 8a 1e 0f b6 db 31 d3 88 1e c7 45 ac 27 01 00 00 8a 1f 80 c3 01 88 1f c7 45 a8 df 01 00 00 8a 1e 8b 95 18 ff ff ff 8b 02 88 18 } //1
		$a_81_1 = {53 74 72 75 6f 4e 6f 73 57 } //1 StruoNosW
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Trickbot_GH_MTB_3{
	meta:
		description = "Trojan:Win32/Trickbot.GH!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {e9 d0 2a 00 00 55 8b ec 81 ec 90 04 00 00 b8 70 00 00 00 66 89 45 94 b9 61 00 00 00 66 89 4d 96 ba 79 00 00 00 66 89 55 98 b8 6c 00 00 00 66 89 45 9a b9 6f 00 00 00 66 89 4d 9c ba 61 00 00 00 66 89 55 9e b8 64 00 00 00 66 89 45 a0 b9 2e 00 00 00 66 89 4d a2 ba 65 00 00 00 66 89 55 a4 b8 78 00 00 00 66 89 45 a6 b9 65 00 00 00 66 89 4d a8 33 d2 66 89 55 aa b8 73 00 00 00 66 89 45 c4 b9 61 00 00 00 66 89 4d c6 ba 6d 00 00 00 66 89 55 c8 b8 70 00 00 00 66 89 45 ca b9 6c 00 00 00 66 89 4d cc ba 65 00 00 00 66 89 55 ce b8 2e 00 00 00 66 89 45 d0 b9 65 00 00 00 66 89 4d d2 ba 78 00 00 00 66 89 55 d4 b8 65 00 00 00 66 89 45 d6 33 c9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}