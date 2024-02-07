
rule Trojan_Win32_Detrahere_E{
	meta:
		description = "Trojan:Win32/Detrahere.E,SIGNATURE_TYPE_PEHSTR,0b 00 0b 00 0a 00 00 0a 00 "
		
	strings :
		$a_01_0 = {4c 62 74 71 66 73 74 6c 7a 21 4d 62 63 } //0a 00  Lbtqfstlz!Mbc
		$a_01_1 = {4e 62 6d 78 62 73 66 63 7a 75 66 74 21 44 70 73 71 70 73 62 75 6a 70 6f } //0a 00  Nbmxbsfczuft!Dpsqpsbujpo
		$a_01_2 = {4e 64 42 67 66 66 2d 21 4a 6f 64 2f } //0a 00  NdBgff-!Jod/
		$a_01_3 = {51 62 6f 65 62 21 54 66 64 76 73 6a 75 7a 21 54 2f 4d } //01 00  Qboeb!Tfdvsjuz!T/M
		$a_01_4 = {5b 4c 52 40 52 42 54 48 2d 64 77 64 } //01 00  [LR@RBTH-dwd
		$a_01_5 = {5b 4c 52 4c 4f 44 4d 46 2d 44 57 44 } //01 00  [LRLODMF-DWD
		$a_01_6 = {5b 40 55 46 54 48 2d 44 57 44 } //01 00  [@UFTH-DWD
		$a_01_7 = {5b 40 55 46 54 48 57 2d 44 57 44 } //01 00  [@UFTHW-DWD
		$a_01_8 = {5b 40 55 40 52 53 52 55 42 2d 44 57 44 } //01 00  [@U@RSRUB-DWD
		$a_01_9 = {5b 40 55 40 52 53 54 48 2d 44 57 44 } //00 00  [@U@RSTH-DWD
		$a_01_10 = {00 7e 15 } //00 00 
	condition:
		any of ($a_*)
 
}