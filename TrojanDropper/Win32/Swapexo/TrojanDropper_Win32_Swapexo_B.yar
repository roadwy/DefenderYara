
rule TrojanDropper_Win32_Swapexo_B{
	meta:
		description = "TrojanDropper:Win32/Swapexo.B,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {47 6c 6f 62 61 6c 5c 74 74 74 6d 6d 6d 74 74 74 00 } //5
		$a_01_1 = {74 74 74 6b 6b 6b 74 74 74 00 } //1 瑴歴歫瑴t
		$a_01_2 = {2f 72 78 78 25 64 3f 64 3d 25 64 26 66 31 3d 25 73 26 66 32 3d 25 73 00 } //1 爯硸搥搿┽♤ㅦ┽♳㉦┽s
		$a_00_3 = {25 73 5c 64 72 69 76 65 72 73 5c 25 73 2e 73 79 73 } //1 %s\drivers\%s.sys
		$a_00_4 = {55 50 44 41 54 45 53 45 52 56 45 52 } //1 UPDATESERVER
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=9
 
}