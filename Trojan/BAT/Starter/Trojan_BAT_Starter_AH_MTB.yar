
rule Trojan_BAT_Starter_AH_MTB{
	meta:
		description = "Trojan:BAT/Starter.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 06 00 00 "
		
	strings :
		$a_00_0 = {28 1d 00 00 0a 28 1e 00 00 0a 0c 08 08 6f 1f 00 00 0a 17 da 28 20 00 00 0a 72 01 00 00 70 28 21 00 00 0a 0a 1d 28 22 00 00 0a 72 0b 00 00 70 06 28 23 00 00 0a 0b 07 28 24 00 00 0a 2d 31 } //10
		$a_80_1 = {47 65 74 46 69 6c 65 4e 61 6d 65 57 69 74 68 6f 75 74 45 78 74 65 6e 73 69 6f 6e } //GetFileNameWithoutExtension  3
		$a_80_2 = {67 65 74 5f 45 78 65 63 75 74 61 62 6c 65 50 61 74 68 } //get_ExecutablePath  3
		$a_80_3 = {47 65 74 46 6f 6c 64 65 72 50 61 74 68 } //GetFolderPath  3
		$a_80_4 = {67 65 74 5f 4c 65 6e 67 74 68 } //get_Length  3
		$a_80_5 = {67 65 74 5f 46 69 6c 65 53 79 73 74 65 6d } //get_FileSystem  3
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3) >=25
 
}