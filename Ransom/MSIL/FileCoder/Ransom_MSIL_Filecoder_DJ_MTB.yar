
rule Ransom_MSIL_Filecoder_DJ_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.DJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {52 45 50 4c 41 43 45 5f 43 4f 4d 4d 41 4e 44 5f 4c 49 4e 45 } //01 00  REPLACE_COMMAND_LINE
		$a_81_1 = {5c 73 79 73 74 65 6d 33 32 5c 63 6d 73 74 70 2e 65 78 65 } //01 00  \system32\cmstp.exe
		$a_81_2 = {43 4d 53 54 50 42 79 70 61 73 73 } //01 00  CMSTPBypass
		$a_81_3 = {47 65 74 52 61 6e 64 6f 6d 46 69 6c 65 4e 61 6d 65 } //01 00  GetRandomFileName
		$a_81_4 = {69 67 2e 65 78 65 } //00 00  ig.exe
	condition:
		any of ($a_*)
 
}
rule Ransom_MSIL_Filecoder_DJ_MTB_2{
	meta:
		description = "Ransom:MSIL/Filecoder.DJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 66 69 6c 65 73 20 68 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //01 00  Your files hve been encrypted
		$a_81_1 = {53 74 61 72 74 20 52 61 6e 73 6f 6d 77 61 72 65 } //01 00  Start Ransomware
		$a_81_2 = {44 65 6c 65 74 65 64 49 74 65 6d 73 2e 74 78 74 } //01 00  DeletedItems.txt
		$a_81_3 = {44 4f 20 4e 4f 54 20 44 45 4c 45 54 45 20 54 48 49 53 20 46 49 4c 45 21 21 20 54 48 49 53 20 46 49 4c 45 20 49 53 20 55 53 45 44 20 46 4f 52 20 44 45 43 52 59 50 54 49 4f 4e } //01 00  DO NOT DELETE THIS FILE!! THIS FILE IS USED FOR DECRYPTION
		$a_81_4 = {66 69 6c 65 73 20 65 6e 63 72 79 70 74 65 64 } //00 00  files encrypted
	condition:
		any of ($a_*)
 
}