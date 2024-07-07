
rule PWS_Win32_OnLineGames_JA_dll{
	meta:
		description = "PWS:Win32/OnLineGames.JA!dll,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 04 85 c9 74 19 8b 44 24 08 85 c0 74 11 7c 0f 8a 14 01 80 f2 30 80 c2 20 88 14 01 48 79 f1 c3 } //1
		$a_01_1 = {7a 68 69 68 75 69 67 75 61 6e } //1 zhihuiguan
		$a_01_2 = {52 58 4a 48 5f 4b 49 43 4b 41 52 53 45 30 2e } //1 RXJH_KICKARSE0.
		$a_01_3 = {25 68 73 3f 75 3d 25 68 73 26 70 3d 75 6e 6b 6e 6f 77 26 63 3d 25 68 73 26 61 63 3d } //1 %hs?u=%hs&p=unknow&c=%hs&ac=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}