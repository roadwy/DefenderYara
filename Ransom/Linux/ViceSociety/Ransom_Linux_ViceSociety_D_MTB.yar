
rule Ransom_Linux_ViceSociety_D_MTB{
	meta:
		description = "Ransom:Linux/ViceSociety.D!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {41 4c 4c 20 59 4f 55 52 20 46 49 4c 45 53 20 48 41 56 45 20 42 45 45 4e 20 45 4e 43 52 59 50 54 45 44 20 42 59 20 56 49 43 45 20 53 4f 43 49 45 54 59 } //01 00  ALL YOUR FILES HAVE BEEN ENCRYPTED BY VICE SOCIETY
		$a_00_1 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 2c 20 50 56 45 2f 56 4d 57 61 72 65 20 69 6e 66 72 61 73 74 72 75 63 74 75 72 65 20 61 6e 64 20 62 61 63 6b 75 70 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //01 00  All your files, PVE/VMWare infrastructure and backups have been encrypted
		$a_00_2 = {2e 52 45 41 44 4d 45 5f 54 4f 5f 52 45 53 54 4f 52 45 } //01 00  .README_TO_RESTORE
		$a_00_3 = {55 73 61 67 65 3a 25 73 20 5b 2d 6d 20 28 31 30 2d 32 30 2d 32 35 2d 33 33 2d 35 30 29 20 5d 20 53 74 61 72 74 20 50 61 74 68 } //01 00  Usage:%s [-m (10-20-25-33-50) ] Start Path
		$a_00_4 = {46 69 6c 65 20 4c 6f 63 6b 65 64 3a 25 73 20 50 49 44 3a 25 64 } //01 00  File Locked:%s PID:%d
		$a_00_5 = {2e 78 78 78 78 } //01 00  .xxxx
		$a_00_6 = {2e 63 72 79 70 74 } //00 00  .crypt
		$a_00_7 = {5d 04 00 } //00 fa 
	condition:
		any of ($a_*)
 
}