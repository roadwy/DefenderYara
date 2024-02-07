
rule Ransom_Win32_Jexcrypt_A{
	meta:
		description = "Ransom:Win32/Jexcrypt.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 00 78 00 65 00 6a 00 79 00 79 00 6b 00 } //01 00  .xejyyk
		$a_01_1 = {57 00 61 00 72 00 6e 00 69 00 6e 00 67 00 20 00 57 00 72 00 6f 00 6e 00 67 00 20 00 57 00 61 00 6c 00 6c 00 65 00 74 00 20 00 41 00 64 00 64 00 72 00 65 00 73 00 73 00 } //01 00  Warning Wrong Wallet Address
		$a_01_2 = {49 00 6d 00 70 00 6f 00 73 00 73 00 69 00 62 00 6c 00 65 00 20 00 74 00 6f 00 20 00 66 00 69 00 6e 00 64 00 20 00 74 00 68 00 65 00 20 00 74 00 72 00 61 00 6e 00 73 00 61 00 63 00 74 00 69 00 6f 00 6e 00 } //01 00  Impossible to find the transaction
		$a_01_3 = {54 00 54 00 69 00 6d 00 65 00 2e 00 } //01 00  TTime.
		$a_01_4 = {6d 00 6b 00 77 00 } //01 00  mkw
		$a_01_5 = {77 6f 72 6b 5c 6d 6c 31 5c 52 65 6c 65 61 73 65 } //00 00  work\ml1\Release
		$a_01_6 = {00 80 10 00 } //00 65 
	condition:
		any of ($a_*)
 
}