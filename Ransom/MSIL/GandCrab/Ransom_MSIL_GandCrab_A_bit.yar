
rule Ransom_MSIL_GandCrab_A_bit{
	meta:
		description = "Ransom:MSIL/GandCrab.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 6e 63 72 79 70 74 46 69 6c 65 } //01 00  EncryptFile
		$a_01_1 = {45 6e 63 72 79 70 74 46 6f 6c 64 65 72 } //01 00  EncryptFolder
		$a_01_2 = {43 72 65 61 74 65 50 61 73 73 } //01 00  CreatePass
		$a_01_3 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //01 00  RijndaelManaged
		$a_01_4 = {53 63 72 65 65 6e 73 68 6f 74 5f 31 } //01 00  Screenshot_1
		$a_01_5 = {77 68 6f 5f 61 63 63 65 70 74 73 5f 62 69 74 63 6f 69 6e 73 5f 61 73 5f 70 61 79 6d 65 6e 74 } //00 00  who_accepts_bitcoins_as_payment
	condition:
		any of ($a_*)
 
}