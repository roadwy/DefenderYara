
rule Ransom_MSIL_FileCryptor_PS_MTB{
	meta:
		description = "Ransom:MSIL/FileCryptor.PS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 61 00 6c 00 6c 00 } //01 00  vssadmin delete shadows /all
		$a_01_1 = {52 00 45 00 41 00 44 00 5f 00 4d 00 45 00 2e 00 68 00 74 00 6d 00 6c 00 } //01 00  READ_ME.html
		$a_01_2 = {2e 00 6c 00 6f 00 63 00 6b 00 65 00 64 00 } //01 00  .locked
		$a_01_3 = {49 00 20 00 61 00 6d 00 20 00 73 00 6f 00 20 00 73 00 6f 00 72 00 72 00 79 00 20 00 21 00 20 00 41 00 6c 00 6c 00 20 00 79 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 68 00 61 00 76 00 65 00 20 00 62 00 65 00 65 00 6e 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 64 00 } //00 00  I am so sorry ! All your files have been encryptd
	condition:
		any of ($a_*)
 
}