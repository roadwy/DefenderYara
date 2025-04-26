
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
rule Ransom_MSIL_Filecoder_ARA_MTB_2{
	meta:
		description = "Ransom:MSIL/Filecoder.ARA!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {59 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 68 00 61 00 76 00 65 00 20 00 62 00 65 00 65 00 6e 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //2 Your files have been encrypted
		$a_01_1 = {62 00 63 00 31 00 71 00 78 00 79 00 32 00 6b 00 67 00 64 00 79 00 67 00 6a 00 72 00 73 00 71 00 74 00 7a 00 71 00 32 00 6e 00 30 00 79 00 72 00 66 00 32 00 34 00 39 00 33 00 70 00 38 00 33 00 6b 00 6b 00 66 00 6a 00 68 00 78 00 30 00 77 00 6c 00 68 00 } //2 bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
		$a_01_2 = {32 00 34 00 20 00 68 00 6f 00 75 00 72 00 73 00 20 00 74 00 6f 00 20 00 74 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00 } //2 24 hours to transfer
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}