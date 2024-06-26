
rule Ransom_MSIL_KillDisk_PAA_MTB{
	meta:
		description = "Ransom:MSIL/KillDisk.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3e 00 3e 00 0a 00 00 0a 00 "
		
	strings :
		$a_01_0 = {6b 69 6c 6c 74 46 69 6c 65 } //0a 00  killtFile
		$a_01_1 = {57 72 69 74 65 46 69 6c 65 } //0a 00  WriteFile
		$a_01_2 = {4b 69 6c 6c 44 69 73 6b } //0a 00  KillDisk
		$a_01_3 = {57 69 70 65 54 79 70 65 } //0a 00  WipeType
		$a_01_4 = {57 69 70 65 50 61 73 73 } //0a 00  WipePass
		$a_01_5 = {4d 62 72 53 69 7a 65 } //01 00  MbrSize
		$a_01_6 = {47 65 74 4c 6f 67 69 63 61 6c 44 72 69 76 65 73 } //01 00  GetLogicalDrives
		$a_01_7 = {67 65 74 5f 50 72 6f 63 65 73 73 4e 61 6d 65 } //01 00  get_ProcessName
		$a_01_8 = {46 69 6c 65 53 79 73 74 65 6d 49 6e 66 6f } //01 00  FileSystemInfo
		$a_01_9 = {67 65 74 5f 44 72 69 76 65 54 79 70 65 } //00 00  get_DriveType
	condition:
		any of ($a_*)
 
}