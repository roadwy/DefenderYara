
rule Trojan_BAT_Raccoon_A_MTB{
	meta:
		description = "Trojan:BAT/Raccoon.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_81_0 = {6c 69 4d 6a 6f 6f 4c 61 59 64 6c 56 75 6a 48 74 79 43 5a 7a 43 77 4d 63 62 41 51 70 41 } //01 00  liMjooLaYdlVujHtyCZzCwMcbAQpA
		$a_81_1 = {78 63 43 79 46 } //01 00  xcCyF
		$a_81_2 = {33 73 52 63 61 63 75 75 6f 38 54 34 7a 2e 72 65 73 6f 75 72 63 65 73 } //01 00  3sRcacuuo8T4z.resources
		$a_81_3 = {67 65 74 5f 53 74 61 72 74 75 70 50 61 74 68 } //01 00  get_StartupPath
		$a_81_4 = {47 65 74 46 6f 6c 64 65 72 50 61 74 68 } //01 00  GetFolderPath
		$a_81_5 = {47 65 74 48 61 73 68 43 6f 64 65 } //01 00  GetHashCode
		$a_81_6 = {5a 69 70 41 72 63 68 69 76 65 4d 6f 64 65 } //01 00  ZipArchiveMode
		$a_81_7 = {49 73 4c 6f 67 67 69 6e 67 } //00 00  IsLogging
	condition:
		any of ($a_*)
 
}