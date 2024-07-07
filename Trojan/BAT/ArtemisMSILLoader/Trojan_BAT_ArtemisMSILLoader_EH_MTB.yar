
rule Trojan_BAT_ArtemisMSILLoader_EH_MTB{
	meta:
		description = "Trojan:BAT/ArtemisMSILLoader.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {48 6a 64 79 6c 7a 72 66 71 6d 71 61 71 61 73 78 64 2e 4e 64 63 78 73 6c 63 68 6e } //1 Hjdylzrfqmqaqasxd.Ndcxslchn
		$a_81_1 = {65 7a 4d 78 59 7a 67 79 5a 6a 4a 6c 4c 57 49 33 59 6a 67 74 4e 44 64 6b 5a 53 31 68 4e 47 49 79 4c 54 5a 6a 59 54 46 69 59 54 52 6a 4d 6a 67 31 4d 58 30 73 49 45 4e 31 62 48 52 31 63 6d 55 39 62 6d 56 31 64 48 4a 68 62 43 77 67 55 48 56 69 62 47 6c 6a 53 32 56 35 56 47 39 72 5a 57 34 39 4d 32 55 31 4e 6a 4d 31 4d 44 59 35 4d 32 59 33 4d 7a 55 31 5a 51 3d 3d } //1 ezMxYzgyZjJlLWI3YjgtNDdkZS1hNGIyLTZjYTFiYTRjMjg1MX0sIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49M2U1NjM1MDY5M2Y3MzU1ZQ==
		$a_81_2 = {49 7a 68 69 74 79 70 76 7a 72 2e 65 78 65 } //1 Izhitypvzr.exe
		$a_81_3 = {61 64 64 5f 52 65 73 6f 75 72 63 65 52 65 73 6f 6c 76 65 } //1 add_ResourceResolve
		$a_81_4 = {47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 4e 61 6d 65 73 } //1 GetManifestResourceNames
		$a_81_5 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}