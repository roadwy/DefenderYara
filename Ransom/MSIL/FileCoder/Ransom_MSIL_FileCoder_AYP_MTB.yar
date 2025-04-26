
rule Ransom_MSIL_FileCoder_AYP_MTB{
	meta:
		description = "Ransom:MSIL/FileCoder.AYP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {52 61 6e 73 32 32 2e 44 65 63 72 79 70 74 6f 72 41 70 70 } //2 Rans22.DecryptorApp
		$a_00_1 = {73 00 75 00 63 00 63 00 65 00 73 00 73 00 66 00 75 00 6c 00 6c 00 79 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 21 00 } //2 successfully encrypted!
		$a_00_2 = {54 00 68 00 65 00 20 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 65 00 78 00 69 00 74 00 73 00 20 00 62 00 65 00 63 00 61 00 75 00 73 00 65 00 20 00 61 00 20 00 64 00 65 00 62 00 75 00 67 00 67 00 65 00 72 00 20 00 77 00 61 00 73 00 20 00 64 00 65 00 74 00 65 00 63 00 74 00 65 00 64 00 2e 00 } //1 The program exits because a debugger was detected.
		$a_01_3 = {45 6e 63 72 79 70 74 46 69 6c 65 } //1 EncryptFile
		$a_01_4 = {53 61 76 65 4d 61 63 68 69 6e 65 49 64 54 6f 53 61 76 65 44 69 72 65 63 74 6f 72 79 } //1 SaveMachineIdToSaveDirectory
		$a_01_5 = {44 65 63 72 79 70 74 46 69 6c 65 73 49 6e 44 69 72 65 63 74 6f 72 79 } //1 DecryptFilesInDirectory
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=8
 
}