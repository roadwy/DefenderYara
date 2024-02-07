
rule Ransom_Win32_BlkCrypt_SL_MTB{
	meta:
		description = "Ransom:Win32/BlkCrypt.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {3c 52 61 6e 73 6f 6d 5f 4e 6f 74 65 5f 4c 6f 61 64 3e } //01 00  <Ransom_Note_Load>
		$a_81_1 = {53 74 61 72 74 5f 45 6e 63 72 79 70 74 } //01 00  Start_Encrypt
		$a_81_2 = {53 75 63 63 65 73 73 3a 20 44 6f 6e 27 74 20 77 6f 72 72 79 2c 20 49 20 77 69 6c 6c 20 64 65 63 72 79 70 74 20 79 6f 75 72 20 66 69 6c 65 73 20 69 6e 20 6a 75 73 74 20 61 20 62 69 74 } //01 00  Success: Don't worry, I will decrypt your files in just a bit
		$a_81_3 = {59 6f 75 20 64 69 64 20 6e 6f 74 20 6d 61 64 65 20 61 20 70 61 79 6d 65 6e 74 21 20 54 72 79 20 61 67 61 69 6e } //01 00  You did not made a payment! Try again
		$a_81_4 = {70 61 79 20 66 6f 72 20 63 6f 64 65 3a 20 49 6e 73 74 61 6e 74 52 61 6e 73 6f 6d 40 67 6d 61 69 6c 2e 63 6f 6d } //00 00  pay for code: InstantRansom@gmail.com
	condition:
		any of ($a_*)
 
}