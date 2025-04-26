
rule Ransom_Win64_TeslaCrypt_AB_MTB{
	meta:
		description = "Ransom:Win64/TeslaCrypt.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_01_0 = {56 3a 5c 67 65 72 69 74 6a 65 69 5c 61 64 6b 6d 67 72 6a 67 69 69 5c 64 66 65 5c 77 66 65 66 2e 70 64 62 } //10 V:\geritjei\adkmgrjgii\dfe\wfef.pdb
		$a_01_1 = {43 6f 49 6e 74 65 72 6e 65 74 43 72 65 61 74 65 5a 6f 6e 65 4d 61 6e 61 67 65 72 } //1 CoInternetCreateZoneManager
		$a_01_2 = {53 65 74 75 70 44 69 47 65 74 41 63 74 75 61 6c 53 65 63 74 69 6f 6e 54 6f 49 6e 73 74 61 6c 6c 41 } //1 SetupDiGetActualSectionToInstallA
		$a_01_3 = {46 69 6e 64 4e 65 78 74 56 6f 6c 75 6d 65 4d 6f 75 6e 74 50 6f 69 6e 74 41 } //1 FindNextVolumeMountPointA
		$a_01_4 = {43 72 65 61 74 65 54 61 70 65 50 61 72 74 69 74 69 6f 6e } //1 CreateTapePartition
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=14
 
}