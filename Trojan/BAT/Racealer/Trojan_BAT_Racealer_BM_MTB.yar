
rule Trojan_BAT_Racealer_BM_MTB{
	meta:
		description = "Trojan:BAT/Racealer.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 "
		
	strings :
		$a_00_0 = {0c 08 08 1f 3c 58 4b e0 58 25 1c 58 49 0d 25 1f 14 58 49 13 04 16 e0 13 05 16 13 06 1f 18 58 11 04 58 13 07 } //10
		$a_80_1 = {4a 69 78 6f 73 64 6a 49 32 } //JixosdjI2  3
		$a_80_2 = {35 4f 55 54 50 55 54 2d 4f 4e 4c 49 4e 45 50 4e 47 54 4f 4f 4c 53 } //5OUTPUT-ONLINEPNGTOOLS  3
		$a_80_3 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //DownloadData  3
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3) >=19
 
}