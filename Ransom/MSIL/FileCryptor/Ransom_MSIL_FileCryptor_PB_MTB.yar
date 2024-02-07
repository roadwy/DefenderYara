
rule Ransom_MSIL_FileCryptor_PB_MTB{
	meta:
		description = "Ransom:MSIL/FileCryptor.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 00 4c 00 4f 00 43 00 4b 00 32 00 47 00 } //01 00  .LOCK2G
		$a_01_1 = {64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 61 00 6c 00 6c 00 20 00 2f 00 71 00 75 00 69 00 65 00 74 00 } //01 00  delete shadows /all /quiet
		$a_01_2 = {68 00 61 00 76 00 65 00 20 00 62 00 65 00 65 00 6e 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 20 00 6f 00 6e 00 20 00 74 00 68 00 69 00 73 00 20 00 50 00 43 00 } //01 00  have been encrypted on this PC
		$a_01_3 = {5c 00 21 00 21 00 21 00 52 00 65 00 63 00 6f 00 76 00 65 00 72 00 79 00 20 00 46 00 69 00 6c 00 65 00 2e 00 74 00 78 00 74 00 } //00 00  \!!!Recovery File.txt
	condition:
		any of ($a_*)
 
}