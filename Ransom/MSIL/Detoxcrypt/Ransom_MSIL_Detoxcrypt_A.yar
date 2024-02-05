
rule Ransom_MSIL_Detoxcrypt_A{
	meta:
		description = "Ransom:MSIL/Detoxcrypt.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 08 00 00 01 00 "
		
	strings :
		$a_80_0 = {44 65 74 6f 78 43 72 79 70 74 6f 5c 44 65 74 6f 78 43 72 79 70 74 6f 5c 6f 62 6a 5c 44 65 62 75 67 5c 4d 69 63 72 6f 73 6f 66 74 48 6f 73 74 2e 70 64 62 } //DetoxCrypto\DetoxCrypto\obj\Debug\MicrosoftHost.pdb  01 00 
		$a_80_1 = {64 65 74 6f 78 63 72 79 70 74 6f 2e 6e 65 74 31 36 2e 6e 65 74 2f 67 65 6e 65 72 61 74 65 2e 70 68 70 } //detoxcrypto.net16.net/generate.php  01 00 
		$a_80_2 = {5c 50 6f 6b 65 6d 6f 6e 5c 6b 65 79 2e 74 78 74 } //\Pokemon\key.txt  01 00 
		$a_80_3 = {5c 50 6f 6b 65 6d 6f 6e 5c 74 6f 74 61 6c 2e 74 78 74 } //\Pokemon\total.txt  01 00 
		$a_80_4 = {4e 6f 20 66 69 6c 65 73 20 63 68 6f 6f 73 65 21 } //No files choose!  01 00 
		$a_80_5 = {3c 47 65 74 46 69 6c 65 73 3e } //<GetFiles>  01 00 
		$a_80_6 = {5c 44 6f 77 6e 6c 6f 61 64 73 5c 50 6f 6b 65 6d 6f 6e 5c 70 6f 6b 62 67 2e 6a 70 67 } //\Downloads\Pokemon\pokbg.jpg  01 00 
		$a_80_7 = {5c 44 6f 77 6e 6c 6f 61 64 73 5c 50 6f 6b 65 6d 6f 6e 5c 50 6f 6b 65 6d 6f 6e 2e 65 78 65 } //\Downloads\Pokemon\Pokemon.exe  00 00 
		$a_00_8 = {5d 04 00 } //00 69 
	condition:
		any of ($a_*)
 
}