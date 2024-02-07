
rule Ransom_MSIL_DutCrypt_PI_MSR{
	meta:
		description = "Ransom:MSIL/DutCrypt.PI!MSR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 00 75 00 63 00 6b 00 6e 00 6f 00 72 00 6b 00 65 00 79 00 } //01 00  fucknorkey
		$a_01_1 = {66 00 75 00 63 00 6b 00 6e 00 6f 00 68 00 77 00 69 00 64 00 } //01 00  fucknohwid
		$a_01_2 = {52 00 61 00 74 00 68 00 65 00 72 00 20 00 68 00 61 00 76 00 65 00 20 00 6d 00 79 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 74 00 61 00 6b 00 65 00 6e 00 20 00 66 00 6f 00 72 00 20 00 72 00 61 00 6e 00 73 00 6f 00 6d 00 20 00 74 00 68 00 61 00 6e 00 20 00 6d 00 79 00 20 00 66 00 61 00 6d 00 69 00 6c 00 79 00 } //01 00  Rather have my files taken for ransom than my family
		$a_01_3 = {4d 61 61 6b 20 32 30 30 20 65 75 72 6f 20 69 6e 20 62 69 74 63 6f 69 6e 20 6f 76 65 72 20 6e 61 61 72 20 68 65 74 20 62 69 74 63 6f 69 6e 20 41 64 72 65 73 20 6f 66 20 73 63 61 6e 20 64 65 20 71 72 20 63 6f 64 65 } //01 00  Maak 200 euro in bitcoin over naar het bitcoin Adres of scan de qr code
		$a_03_4 = {5c 57 69 6e 64 6f 77 73 44 65 66 65 6e 64 65 72 5c 6f 62 6a 5c 90 02 10 5c 41 70 70 6c 69 63 61 74 69 6f 6e 5f 44 65 66 2e 70 64 62 90 00 } //00 00 
		$a_00_5 = {5d 04 00 } //00 18 
	condition:
		any of ($a_*)
 
}