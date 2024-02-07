
rule Trojan_BAT_RedLineStealer_MAI_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.MAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0f 00 00 01 00 "
		
	strings :
		$a_81_0 = {31 32 37 66 38 65 38 62 2d 32 35 35 31 2d 34 38 33 66 2d 38 30 66 37 2d 62 63 38 36 31 34 30 36 31 63 34 31 } //01 00  127f8e8b-2551-483f-80f7-bc8614061c41
		$a_81_1 = {48 6f 74 73 70 6f 74 20 53 68 69 65 6c 64 20 37 2e 39 2e 30 } //01 00  Hotspot Shield 7.9.0
		$a_81_2 = {4f 6e 68 79 64 65 6c 72 6f 71 77 6d 74 79 77 6f 69 77 71 7a } //01 00  Onhydelroqwmtywoiwqz
		$a_81_3 = {70 6f 77 65 72 73 68 65 6c 6c } //01 00  powershell
		$a_81_4 = {54 65 73 74 2d 43 6f 6e 6e 65 63 74 69 6f 6e } //01 00  Test-Connection
		$a_81_5 = {67 6f 6f 67 6c 65 } //01 00  google
		$a_81_6 = {66 61 63 65 62 6f 6f 6b } //01 00  facebook
		$a_81_7 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00  InvokeMember
		$a_81_8 = {47 65 74 42 79 74 65 73 } //01 00  GetBytes
		$a_81_9 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_81_10 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //01 00  RijndaelManaged
		$a_81_11 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_81_12 = {43 69 70 68 65 72 4d 6f 64 65 } //01 00  CipherMode
		$a_81_13 = {43 72 79 70 74 6f 53 74 72 65 61 6d } //01 00  CryptoStream
		$a_81_14 = {73 65 74 5f 4b 65 79 53 69 7a 65 } //00 00  set_KeySize
	condition:
		any of ($a_*)
 
}