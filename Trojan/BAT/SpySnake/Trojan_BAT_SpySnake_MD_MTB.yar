
rule Trojan_BAT_SpySnake_MD_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 07 11 09 9a 1f 10 28 90 01 03 0a 6f 90 01 03 0a 00 11 09 17 58 13 09 11 09 07 8e 69 fe 04 13 0a 11 0a 2d db 90 00 } //10
		$a_03_1 = {25 16 11 06 16 9a a2 25 17 11 06 17 9a a2 25 18 72 90 01 03 70 a2 13 07 11 05 90 00 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}
rule Trojan_BAT_SpySnake_MD_MTB_2{
	meta:
		description = "Trojan:BAT/SpySnake.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_03_0 = {0b 07 8e 69 17 da 0c 2b 13 06 07 08 93 28 90 01 03 0a 28 90 01 03 0a 0a 08 15 d6 0c 08 16 2f e9 90 00 } //10
		$a_01_1 = {52 65 76 65 72 73 65 53 74 72 69 6e 67 } //1 ReverseString
		$a_01_2 = {67 65 74 5f 57 65 62 42 72 6f 77 73 65 72 } //1 get_WebBrowser
		$a_01_3 = {46 69 6c 65 44 6f 77 6e 6c 6f 61 64 } //1 FileDownload
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=13
 
}
rule Trojan_BAT_SpySnake_MD_MTB_3{
	meta:
		description = "Trojan:BAT/SpySnake.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 10 00 00 "
		
	strings :
		$a_81_0 = {30 66 66 61 30 39 33 63 2d 39 63 30 64 2d 34 33 39 38 2d 62 63 31 62 2d 35 36 33 39 38 36 37 34 33 61 35 62 } //1 0ffa093c-9c0d-4398-bc1b-563986743a5b
		$a_81_1 = {52 79 61 6e 20 41 64 61 6d 73 } //1 Ryan Adams
		$a_81_2 = {4a 6f 62 4d 61 6e 61 67 65 72 4d 6f 6e 69 74 6f 72 } //1 JobManagerMonitor
		$a_81_3 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_81_4 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_81_5 = {67 65 74 5f 53 6e 61 70 73 68 6f 74 4f 6e 53 68 75 74 64 6f 77 6e } //1 get_SnapshotOnShutdown
		$a_81_6 = {67 65 74 5f 53 6e 61 70 73 68 6f 74 4e 61 6d 65 } //1 get_SnapshotName
		$a_81_7 = {6c 6f 63 6b 65 64 56 4d 73 } //1 lockedVMs
		$a_81_8 = {67 65 74 5f 43 6c 6f 6e 65 4f 6e 53 68 75 74 64 6f 77 6e } //1 get_CloneOnShutdown
		$a_81_9 = {4c 6f 63 6b 56 4d 43 6f 6d 6d 61 6e 64 } //1 LockVMCommand
		$a_81_10 = {57 72 69 74 65 54 6f 44 69 72 52 65 6e 61 6d 65 } //1 WriteToDirRename
		$a_81_11 = {67 65 74 5f 4b 65 79 } //1 get_Key
		$a_81_12 = {47 65 74 53 74 72 69 6e 67 } //1 GetString
		$a_81_13 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_14 = {67 65 74 5f 4d 61 63 68 69 6e 65 4e 61 6d 65 } //1 get_MachineName
		$a_81_15 = {61 64 64 5f 4b 65 79 55 70 } //1 add_KeyUp
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1+(#a_81_14  & 1)*1+(#a_81_15  & 1)*1) >=16
 
}