
rule Trojan_Win32_Emotet_DGJ_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DGJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_02_0 = {0f b6 c9 03 c1 8b cb 99 f7 f9 8b 84 24 90 01 04 8a 5c 14 24 8b 54 24 1c 32 1c 02 90 00 } //1
		$a_81_1 = {39 78 67 6e 69 65 34 4f 73 69 39 4f 68 47 67 4f 44 57 54 78 6d 35 57 54 62 6f 77 35 67 39 33 48 42 48 32 33 66 6c 37 35 62 33 62 57 76 69 41 44 76 } //1 9xgnie4Osi9OhGgODWTxm5WTbow5g93HBH23fl75b3bWviADv
		$a_81_2 = {35 54 46 4c 61 6e 59 47 41 47 32 34 5a 51 65 58 6e 4a 45 36 78 43 68 6a 45 67 64 35 37 5a 42 6f 33 4f 71 54 7a 35 48 6d 4d } //1 5TFLanYGAG24ZQeXnJE6xChjEgd57ZBo3OqTz5HmM
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=1
 
}