
rule Ransom_MSIL_FileCryptor_B_MTB{
	meta:
		description = "Ransom:MSIL/FileCryptor.B!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 42 00 79 00 74 00 65 00 4c 00 6f 00 63 00 6b 00 65 00 72 00 } //01 00  Software\ByteLocker
		$a_01_1 = {45 6e 63 72 79 70 74 46 6f 6c 64 65 72 } //01 00  EncryptFolder
		$a_01_2 = {24 00 72 00 65 00 63 00 79 00 63 00 6c 00 65 00 2e 00 62 00 69 00 6e 00 } //01 00  $recycle.bin
		$a_01_3 = {2e 00 62 00 79 00 74 00 63 00 72 00 79 00 70 00 74 00 74 00 6d 00 70 00 } //01 00  .bytcrypttmp
		$a_01_4 = {43 00 75 00 72 00 72 00 65 00 6e 00 74 00 46 00 69 00 6c 00 65 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00 } //01 00  CurrentFileDecrypt
		$a_01_5 = {59 00 6f 00 75 00 72 00 20 00 70 00 65 00 72 00 73 00 6f 00 6e 00 61 00 6c 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 61 00 72 00 65 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 21 00 } //00 00  Your personal files are encrypted!
	condition:
		any of ($a_*)
 
}