
rule Ransom_MSIL_FileCoder_AYJ_MTB{
	meta:
		description = "Ransom:MSIL/FileCoder.AYJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_00_0 = {47 00 68 00 6f 00 73 00 74 00 43 00 72 00 79 00 } //2 GhostCry
		$a_01_1 = {24 63 34 33 36 38 37 34 33 2d 32 35 34 33 2d 34 37 39 61 2d 38 61 32 31 2d 34 66 65 61 61 30 36 31 64 66 63 32 } //1 $c4368743-2543-479a-8a21-4feaa061dfc2
		$a_00_2 = {45 00 6e 00 63 00 72 00 79 00 70 00 74 00 69 00 6f 00 6e 00 20 00 63 00 6f 00 6d 00 70 00 6c 00 65 00 74 00 65 00 } //1 Encryption complete
		$a_01_3 = {43 72 65 61 74 65 4d 75 74 65 78 41 6e 64 57 72 69 74 65 54 6f 52 65 67 69 73 74 72 79 } //1 CreateMutexAndWriteToRegistry
		$a_01_4 = {45 6e 63 72 79 70 74 46 69 6c 65 73 } //1 EncryptFiles
	condition:
		((#a_00_0  & 1)*2+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}