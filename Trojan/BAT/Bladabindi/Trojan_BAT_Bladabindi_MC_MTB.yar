
rule Trojan_BAT_Bladabindi_MC_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_03_0 = {13 06 11 06 16 72 90 01 03 70 a2 11 06 0c 07 08 16 6f 90 01 03 0a 0d 17 13 04 2b 3f 00 02 09 11 04 9a 28 90 01 03 0a 28 90 01 03 06 13 05 06 09 11 04 17 58 9a 28 90 01 03 0a 11 05 28 90 01 03 0a 00 06 09 11 04 17 58 9a 28 90 01 03 0a 28 90 01 03 0a 26 00 11 04 18 58 13 04 11 04 09 28 90 01 03 2b 17 59 fe 04 13 07 11 07 90 00 } //01 00 
		$a_01_1 = {47 65 74 54 65 6d 70 50 61 74 68 } //01 00  GetTempPath
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_3 = {4b 69 6c 6c } //01 00  Kill
		$a_01_4 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //01 00  RijndaelManaged
		$a_01_5 = {55 6e 73 65 63 75 72 65 } //01 00  Unsecure
		$a_01_6 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_7 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00  TransformFinalBlock
		$a_01_8 = {73 65 74 5f 4b 65 79 } //00 00  set_Key
	condition:
		any of ($a_*)
 
}