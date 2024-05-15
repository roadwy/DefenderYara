
rule Ransom_MSIL_FileCoder_MVI_MTB{
	meta:
		description = "Ransom:MSIL/FileCoder.MVI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {50 65 64 6f 43 72 79 70 74 65 72 } //01 00  PedoCrypter
		$a_00_1 = {66 69 6c 65 45 78 74 65 6e 73 69 6f 6e 73 } //01 00  fileExtensions
		$a_80_2 = {21 21 21 59 4f 55 52 20 46 49 4c 45 20 48 41 53 20 42 45 45 4e 20 45 4e 43 52 59 50 54 45 44 21 21 21 2e 74 78 74 } //!!!YOUR FILE HAS BEEN ENCRYPTED!!!.txt  01 00 
		$a_80_3 = {41 31 63 30 72 44 65 63 72 79 70 74 } //A1c0rDecrypt  00 00 
	condition:
		any of ($a_*)
 
}