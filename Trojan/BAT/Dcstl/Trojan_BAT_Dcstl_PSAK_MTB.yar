
rule Trojan_BAT_Dcstl_PSAK_MTB{
	meta:
		description = "Trojan:BAT/Dcstl.PSAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //01 00  DebuggingModes
		$a_01_1 = {41 65 73 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //01 00  AesCryptoServiceProvider
		$a_01_2 = {53 79 6d 6d 65 74 72 69 63 41 6c 67 6f 72 69 74 68 6d } //01 00  SymmetricAlgorithm
		$a_01_3 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //01 00  RijndaelManaged
		$a_01_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_5 = {43 6f 6d 70 75 74 65 48 61 73 68 } //01 00  ComputeHash
		$a_01_6 = {42 43 57 76 63 4e 57 30 4a 78 59 6c 4b 4d 51 75 49 78 69 } //01 00  BCWvcNW0JxYlKMQuIxi
		$a_01_7 = {6e 72 79 54 43 62 57 41 37 38 48 4b 78 45 30 66 6b 67 71 } //01 00  nryTCbWA78HKxE0fkgq
		$a_01_8 = {56 73 46 79 76 57 5a 6d 41 75 39 51 67 6f 6e 56 67 74 62 } //01 00  VsFyvWZmAu9QgonVgtb
		$a_01_9 = {6d 64 4c 4c 6f 4c 57 37 59 42 6b 35 73 6a 34 43 6a 4b 34 } //01 00  mdLLoLW7YBk5sj4CjK4
		$a_01_10 = {53 4b 4c 53 62 6f 5a 44 43 64 58 42 71 4b 4d 68 6a 66 55 } //00 00  SKLSboZDCdXBqKMhjfU
	condition:
		any of ($a_*)
 
}