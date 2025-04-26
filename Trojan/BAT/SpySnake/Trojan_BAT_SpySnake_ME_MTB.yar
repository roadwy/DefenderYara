
rule Trojan_BAT_SpySnake_ME_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 06 11 08 9a 1f 10 28 74 00 00 0a 8c 54 00 00 01 6f 75 00 00 0a 26 11 08 17 58 13 08 11 08 06 8e 69 fe 04 13 09 11 09 2d d6 } //10
		$a_01_1 = {25 16 11 05 16 9a a2 25 17 11 05 17 9a a2 25 18 72 8f 04 00 70 a2 13 06 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}
rule Trojan_BAT_SpySnake_ME_MTB_2{
	meta:
		description = "Trojan:BAT/SpySnake.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_01_0 = {57 97 a2 3d 09 0b 00 00 00 00 00 00 00 00 00 00 01 00 00 00 8d 00 00 00 32 00 00 00 8e } //10
		$a_01_1 = {41 70 70 4b 61 74 61 43 73 76 56 69 65 77 65 72 2e 50 72 6f 70 65 72 74 69 65 73 } //1 AppKataCsvViewer.Properties
		$a_01_2 = {66 66 38 36 38 61 32 35 2d 34 34 39 36 2d 34 36 33 61 2d 62 35 35 65 2d 37 38 64 65 30 61 34 35 39 31 35 66 } //1 ff868a25-4496-463a-b55e-78de0a45915f
		$a_01_3 = {43 6f 6e 74 72 6f 6c 43 6f 6c 6c 65 63 74 69 6f 6e } //1 ControlCollection
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=13
 
}
rule Trojan_BAT_SpySnake_ME_MTB_3{
	meta:
		description = "Trojan:BAT/SpySnake.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {2f 00 36 00 39 00 60 00 31 00 2e 00 39 00 60 00 34 00 31 00 2e 00 30 00 39 00 2e 00 31 00 60 00 31 00 31 00 2f 00 2f 00 3a 00 70 00 74 00 60 00 74 00 68 00 } //1 /69`1.9`41.09.1`11//:pt`th
		$a_01_1 = {68 00 73 00 73 00 73 00 73 00 73 00 73 00 6f 00 6b 00 } //1 hssssssok
		$a_01_2 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_4 = {64 75 63 6b 63 68 6f 69 63 65 73 65 6c 65 63 74 6f 72 } //1 duckchoiceselector
		$a_01_5 = {47 69 6d 6d 65 61 64 75 63 6b } //1 Gimmeaduck
		$a_01_6 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_7 = {75 73 65 72 6e 61 6d 65 } //1 username
		$a_01_8 = {64 75 63 6b 6e 61 6d 65 73 74 6f 75 73 65 } //1 ducknamestouse
		$a_01_9 = {63 00 6f 00 6f 00 6b 00 69 00 65 00 } //1 cookie
		$a_01_10 = {66 00 69 00 78 00 65 00 64 00 68 00 6f 00 73 00 74 00 2e 00 6d 00 6f 00 64 00 75 00 6c 00 61 00 74 00 69 00 6f 00 6e 00 } //1 fixedhost.modulation
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}