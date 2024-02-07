
rule Ransom_MSIL_AESLocker_DB_MTB{
	meta:
		description = "Ransom:MSIL/AESLocker.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {41 45 53 2d 4c 6f 63 6b 65 72 } //01 00  AES-Locker
		$a_81_1 = {53 65 74 57 61 6c 6c 70 61 70 65 72 } //01 00  SetWallpaper
		$a_81_2 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //01 00  DebuggingModes
		$a_81_3 = {4b 4d 53 43 6f 6e 6e 65 63 74 69 6f 6e } //01 00  KMSConnection
		$a_81_4 = {6c 6f 63 6b 2e 74 78 74 } //00 00  lock.txt
	condition:
		any of ($a_*)
 
}