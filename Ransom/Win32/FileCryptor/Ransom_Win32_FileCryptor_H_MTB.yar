
rule Ransom_Win32_FileCryptor_H_MTB{
	meta:
		description = "Ransom:Win32/FileCryptor.H!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {2e 00 64 00 61 00 74 00 61 00 5f 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //01 00  .data_encrypted
		$a_00_1 = {2e 00 70 00 61 00 73 00 73 00 77 00 64 00 } //01 00  .passwd
		$a_02_2 = {2e 00 64 00 6f 00 63 00 90 02 10 2e 00 64 00 6f 00 63 00 78 00 90 02 10 2e 00 78 00 6c 00 73 00 90 02 10 2e 00 78 00 6c 00 73 00 78 00 90 00 } //01 00 
		$a_00_3 = {70 61 73 73 77 6f 72 64 42 79 74 65 73 } //01 00  passwordBytes
		$a_00_4 = {62 79 74 65 73 54 6f 42 65 45 6e 63 72 79 70 74 65 64 } //01 00  bytesToBeEncrypted
		$a_00_5 = {62 00 69 00 74 00 63 00 6f 00 69 00 6e 00 } //00 00  bitcoin
		$a_00_6 = {5d 04 00 00 } //1c 25 
	condition:
		any of ($a_*)
 
}