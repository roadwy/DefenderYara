
rule Ransom_Win32_Pitroxin_A{
	meta:
		description = "Ransom:Win32/Pitroxin.A,SIGNATURE_TYPE_PEHSTR,0f 00 0f 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {4f 6f 6f 70 73 2c 79 6f 75 72 20 69 6d 70 6f 72 74 61 6e 74 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //05 00  Ooops,your important files are encrypted
		$a_01_1 = {49 66 20 79 6f 75 20 73 65 65 20 74 68 69 73 20 74 65 78 74 2c 74 68 65 6e 20 79 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 6e 6f 74 20 61 63 63 65 73 73 69 62 6c 65 } //05 00  If you see this text,then your files are not accessible
		$a_01_2 = {4e 6f 62 6f 64 79 20 63 61 6e 20 72 65 63 6f 76 65 72 20 79 6f 75 72 20 66 69 6c 65 73 20 77 69 74 68 6f 75 74 20 6f 75 72 20 64 65 63 72 79 70 74 69 6f 6e 20 73 65 72 76 69 63 65 } //05 00  Nobody can recover your files without our decryption service
		$a_01_3 = {50 6c 65 61 73 65 20 53 65 6e 64 20 24 33 30 30 20 77 6f 72 74 68 20 6f 66 20 42 69 74 63 6f 69 6e 20 74 6f 20 74 68 69 73 20 61 64 64 72 65 73 73 } //05 00  Please Send $300 worth of Bitcoin to this address
		$a_01_4 = {31 47 5a 43 77 34 35 33 4d 7a 51 72 38 56 32 56 41 67 4a 70 52 6d 4b 42 59 52 44 55 4a 38 6b 7a 63 6f } //00 00  1GZCw453MzQr8V2VAgJpRmKBYRDUJ8kzco
		$a_01_5 = {00 67 16 00 00 38 9e 17 fe f7 } //34 66 
	condition:
		any of ($a_*)
 
}