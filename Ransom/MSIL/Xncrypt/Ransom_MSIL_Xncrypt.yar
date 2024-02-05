
rule Ransom_MSIL_Xncrypt{
	meta:
		description = "Ransom:MSIL/Xncrypt,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_80_0 = {59 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 68 61 73 20 62 65 65 6e 20 69 6e 66 65 63 74 65 64 } //Your computer has been infected  01 00 
		$a_80_1 = {70 61 73 73 77 6f 72 64 20 74 6f 20 65 6e 63 72 79 70 74 20 61 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 } //password to encrypt all your files  01 00 
		$a_80_2 = {42 69 74 63 6f 69 6e 20 57 61 6c 6c 65 74 } //Bitcoin Wallet  01 00 
		$a_80_3 = {41 74 74 65 6e 74 69 6f 6e } //Attention  01 00 
		$a_80_4 = {41 6c 6c 20 46 69 6c 65 73 20 45 6e 63 72 79 70 74 65 64 } //All Files Encrypted  01 00 
		$a_80_5 = {4d 69 63 72 6f 73 6f 66 74 2e 56 69 73 75 61 6c 42 61 73 69 63 } //Microsoft.VisualBasic  00 00 
	condition:
		any of ($a_*)
 
}