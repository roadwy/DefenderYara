
rule Ransom_MSIL_Cryptolocker_MA_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 37 34 66 65 66 36 32 2d 36 38 38 62 2d 34 36 38 31 2d 62 61 37 31 2d 34 61 34 64 65 62 30 38 63 61 31 36 } //01 00  e74fef62-688b-4681-ba71-4a4deb08ca16
		$a_01_1 = {2f 00 44 00 50 00 5f 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //01 00  /DP_Decrypter.exe
		$a_01_2 = {2f 00 45 00 78 00 74 00 72 00 61 00 4b 00 65 00 79 00 2e 00 64 00 70 00 } //01 00  /ExtraKey.dp
		$a_01_3 = {2f 00 74 00 3a 00 77 00 69 00 6e 00 65 00 78 00 65 00 } //01 00  /t:winexe
		$a_01_4 = {44 00 45 00 43 00 52 00 59 00 50 00 54 00 20 00 4d 00 59 00 20 00 46 00 49 00 4c 00 45 00 53 00 } //01 00  DECRYPT MY FILES
		$a_01_5 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  ToBase64String
		$a_01_6 = {47 65 74 42 79 74 65 73 } //01 00  GetBytes
		$a_01_7 = {61 64 6d 4b 65 79 54 42 } //01 00  admKeyTB
		$a_01_8 = {70 75 74 68 54 42 } //01 00  puthTB
		$a_01_9 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_10 = {67 65 74 5f 44 50 5f 4b 65 79 67 65 6e } //00 00  get_DP_Keygen
	condition:
		any of ($a_*)
 
}