
rule Ransom_Win64_LockFile_DB_MTB{
	meta:
		description = "Ransom:Win64/LockFile.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {63 6d 64 6e 65 74 63 6f 6e 66 69 67 73 74 61 72 74 3d 64 69 73 61 62 6c 65 64 46 61 69 6c 65 64 20 74 6f 20 77 69 70 65 } //cmdnetconfigstart=disabledFailed to wipe  1
		$a_80_1 = {57 69 6e 64 6f 77 73 20 55 70 64 61 74 65 20 73 79 73 74 65 6d 20 63 6f 72 72 75 70 74 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 } //Windows Update system corrupted successfully  1
		$a_80_2 = {2f 68 6f 6d 65 2f 6d 65 64 75 73 61 2f } ///home/medusa/  1
		$a_80_3 = {63 6d 64 2e 65 78 65 20 2f 65 3a 4f 4e 20 2f 76 3a 4f 46 46 20 2f 64 20 2f 63 } //cmd.exe /e:ON /v:OFF /d /c  1
		$a_80_4 = {4f 6e 63 65 20 69 6e 73 74 61 6e 63 65 20 68 61 73 20 70 72 65 76 69 6f 75 73 6c 79 20 62 65 65 6e 20 70 6f 69 73 6f 6e 65 64 } //Once instance has previously been poisoned  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}