
rule Ransom_MSIL_FileCoder_AZ_MTB{
	meta:
		description = "Ransom:MSIL/FileCoder.AZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {41 63 65 52 61 6e 73 6f 6d 77 61 72 65 } //01 00  AceRansomware
		$a_81_1 = {65 6e 63 72 79 70 74 65 64 46 69 6c 65 73 } //01 00  encryptedFiles
		$a_81_2 = {44 69 73 61 62 6c 65 54 73 6b 4d 47 52 } //01 00  DisableTskMGR
		$a_81_3 = {65 78 74 65 6e 73 69 6f 6e 73 54 6f 45 6e 63 72 79 70 74 } //01 00  extensionsToEncrypt
		$a_81_4 = {44 72 6f 70 44 65 63 72 79 70 74 65 72 } //01 00  DropDecrypter
		$a_81_5 = {41 63 65 44 6f 74 4e 65 74 2e 64 6c 6c } //00 00  AceDotNet.dll
	condition:
		any of ($a_*)
 
}