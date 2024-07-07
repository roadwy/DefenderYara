
rule Worm_Win32_Yahos_A{
	meta:
		description = "Worm:Win32/Yahos.A,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 "
		
	strings :
		$a_01_0 = {6d 47 fe 74 e8 bf c2 45 90 35 d1 5e 33 0a 24 6d } //5
		$a_00_1 = {49 6e 76 69 74 65 20 79 6f 75 72 20 66 72 69 65 6e 64 73 20 74 6f 20 47 6f 6f 67 6c 65 20 54 61 6c 6b } //1 Invite your friends to Google Talk
		$a_00_2 = {25 73 3a 2a 3a 45 6e 61 62 6c 65 64 3a 25 73 } //1 %s:*:Enabled:%s
		$a_00_3 = {42 6c 61 73 74 20 49 4d } //1 Blast IM
		$a_00_4 = {6d 00 69 00 72 00 61 00 20 00 65 00 73 00 74 00 61 00 20 00 66 00 6f 00 74 00 6f 00 } //1 mira esta foto
		$a_00_5 = {6b 00 69 00 6c 00 20 00 62 00 61 00 78 00 6d 00 61 00 71 00 } //1 kil baxmaq
	condition:
		((#a_01_0  & 1)*5+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=9
 
}