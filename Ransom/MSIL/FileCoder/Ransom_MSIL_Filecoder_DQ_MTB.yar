
rule Ransom_MSIL_Filecoder_DQ_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.DQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {44 4f 20 4e 4f 54 20 52 55 4e 20 41 4e 59 20 41 4e 54 49 2d 56 49 52 55 53 20 50 52 4f 47 52 41 4d } //1 DO NOT RUN ANY ANTI-VIRUS PROGRAM
		$a_81_1 = {44 55 52 49 4e 47 20 44 45 43 52 59 50 54 49 4f 4e 2c 20 44 4f 20 4e 4f 54 20 4f 50 45 4e 20 41 4e 59 20 44 41 4d 41 47 45 44 20 46 49 4c 45 } //1 DURING DECRYPTION, DO NOT OPEN ANY DAMAGED FILE
		$a_81_2 = {44 4f 20 4e 4f 54 20 54 52 59 20 54 4f 20 44 45 43 52 59 50 54 20 46 49 4c 45 53 20 57 49 54 48 20 41 4e 4f 54 48 45 52 20 50 52 4f 47 52 41 4d } //1 DO NOT TRY TO DECRYPT FILES WITH ANOTHER PROGRAM
		$a_81_3 = {44 4f 20 4e 4f 54 20 43 48 41 4e 47 45 20 54 48 45 20 45 58 54 45 4e 53 49 4f 4e 20 4f 46 20 54 48 45 20 45 4e 43 52 59 50 54 45 44 20 46 49 4c 45 53 } //1 DO NOT CHANGE THE EXTENSION OF THE ENCRYPTED FILES
		$a_81_4 = {45 78 74 65 6e 73 69 6f 6e 73 54 6f 45 6e 63 72 79 70 74 } //1 ExtensionsToEncrypt
		$a_81_5 = {49 27 6d 20 72 75 6e 6e 69 6e 67 20 69 6e 20 44 65 62 75 67 20 6d 6f 64 65 } //1 I'm running in Debug mode
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}