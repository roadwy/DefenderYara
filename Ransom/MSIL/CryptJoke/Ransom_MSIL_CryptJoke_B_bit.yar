
rule Ransom_MSIL_CryptJoke_B_bit{
	meta:
		description = "Ransom:MSIL/CryptJoke.B!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 72 79 70 74 6f 4a 6f 6b 65 72 5c 43 72 79 70 74 6f 4a 6f 6b 65 72 47 55 49 5c 6f 62 6a 5c 44 65 62 75 67 5c 43 72 79 70 74 6f 4a 6f 6b 65 72 2e 70 64 62 } //01 00  CryptoJoker\CryptoJokerGUI\obj\Debug\CryptoJoker.pdb
		$a_01_1 = {42 00 69 00 74 00 63 00 6f 00 69 00 6e 00 20 00 41 00 64 00 64 00 72 00 65 00 73 00 73 00 } //01 00  Bitcoin Address
		$a_01_2 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_3 = {63 00 6c 00 69 00 63 00 6b 00 20 00 6d 00 65 00 20 00 74 00 6f 00 20 00 64 00 65 00 63 00 72 00 79 00 70 00 74 00 20 00 79 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 } //00 00  click me to decrypt your files
	condition:
		any of ($a_*)
 
}