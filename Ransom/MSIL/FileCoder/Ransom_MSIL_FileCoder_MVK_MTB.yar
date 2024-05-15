
rule Ransom_MSIL_FileCoder_MVK_MTB{
	meta:
		description = "Ransom:MSIL/FileCoder.MVK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {46 69 6c 65 45 6e 63 72 79 2e 70 64 62 } //01 00  FileEncry.pdb
		$a_01_1 = {76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 73 00 } //01 00  vssadmin delete shadows
		$a_00_2 = {42 6f 75 6e 63 79 43 61 73 74 6c 65 } //00 00  BouncyCastle
	condition:
		any of ($a_*)
 
}