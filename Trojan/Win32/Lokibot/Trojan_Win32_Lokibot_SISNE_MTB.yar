
rule Trojan_Win32_Lokibot_SISNE_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.SISNE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 55 14 52 8b 45 10 50 8b 4d 0c 51 8b 55 08 52 } //5
		$a_01_1 = {35 8b 45 1c 99 2b c2 d1 f8 8b 55 18 0f b6 04 02 } //5
		$a_01_2 = {5e e3 f5 06 81 62 35 2b 76 16 55 64 21 2b d1 68 86 c1 77 1b c9 8d 63 bb c3 d9 99 95 89 52 e4 69 } //10
		$a_01_3 = {1b 9d cd bf 6d e1 23 ee 6b e0 3d a5 82 c1 7b df 01 3c 2d c4 2f 72 1e 88 f2 39 58 35 cb b6 c2 17 } //10
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10) >=10
 
}