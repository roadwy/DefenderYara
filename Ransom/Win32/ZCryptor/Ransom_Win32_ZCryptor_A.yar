
rule Ransom_Win32_ZCryptor_A{
	meta:
		description = "Ransom:Win32/ZCryptor.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 52 65 6c 65 61 73 65 5c 4d 79 45 6e 63 72 79 70 74 65 72 32 2e 70 64 62 00 } //01 00  剜汥慥敳䵜䕹据祲瑰牥⸲摰b
		$a_01_1 = {7a 63 72 79 70 74 2e 65 78 65 00 } //01 00 
		$a_01_2 = {5c 48 6f 77 20 74 6f 20 64 65 63 72 79 70 74 20 66 69 6c 65 73 2e 68 74 6d 6c 00 } //01 00 
		$a_01_3 = {41 4c 4c 20 59 4f 55 52 20 50 45 52 53 4f 4e 41 4c 20 46 49 4c 45 53 20 41 52 45 20 45 4e 43 52 59 50 54 45 44 3c 2f 66 6f 6e 74 3e 3c 2f 70 3e } //01 00  ALL YOUR PERSONAL FILES ARE ENCRYPTED</font></p>
		$a_01_4 = {5b 48 6f 77 20 54 6f 20 44 65 63 72 79 70 74 20 59 6f 75 72 20 46 69 6c 65 73 5d 3c } //01 00  [How To Decrypt Your Files]<
		$a_01_5 = {61 75 74 6f 72 75 6e 2e 69 6e 66 00 } //01 00 
		$a_00_6 = {0f 1f 44 00 00 8d 41 2e 30 44 0d e4 41 83 f9 0b 72 f3 8d 45 e4 c6 45 ef 00 50 68 04 01 00 00 } //00 00 
		$a_00_7 = {5d 04 00 00 } //84 7c 
	condition:
		any of ($a_*)
 
}