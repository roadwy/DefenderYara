
rule Ransom_MSIL_Filecoder_ARA_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 61 6e 73 6f 6d 77 61 72 65 48 61 6e 64 6c 65 72 } //2 RansomwareHandler
		$a_01_1 = {45 6e 63 72 79 70 74 46 69 6c 65 73 49 6e 44 72 69 76 65 } //2 EncryptFilesInDrive
		$a_01_2 = {45 6e 63 72 79 70 74 46 69 6c 65 73 49 6e 44 69 72 65 63 74 6f 72 79 } //2 EncryptFilesInDirectory
		$a_00_3 = {56 00 69 00 63 00 74 00 69 00 6d 00 } //2 Victim
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_00_3  & 1)*2) >=8
 
}