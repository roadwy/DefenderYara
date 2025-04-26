
rule Ransom_MSIL_KillDisk_PAA_MTB{
	meta:
		description = "Ransom:MSIL/KillDisk.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3e 00 3e 00 0a 00 00 "
		
	strings :
		$a_01_0 = {6b 69 6c 6c 74 46 69 6c 65 } //10 killtFile
		$a_01_1 = {57 72 69 74 65 46 69 6c 65 } //10 WriteFile
		$a_01_2 = {4b 69 6c 6c 44 69 73 6b } //10 KillDisk
		$a_01_3 = {57 69 70 65 54 79 70 65 } //10 WipeType
		$a_01_4 = {57 69 70 65 50 61 73 73 } //10 WipePass
		$a_01_5 = {4d 62 72 53 69 7a 65 } //10 MbrSize
		$a_01_6 = {47 65 74 4c 6f 67 69 63 61 6c 44 72 69 76 65 73 } //1 GetLogicalDrives
		$a_01_7 = {67 65 74 5f 50 72 6f 63 65 73 73 4e 61 6d 65 } //1 get_ProcessName
		$a_01_8 = {46 69 6c 65 53 79 73 74 65 6d 49 6e 66 6f } //1 FileSystemInfo
		$a_01_9 = {67 65 74 5f 44 72 69 76 65 54 79 70 65 } //1 get_DriveType
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=62
 
}