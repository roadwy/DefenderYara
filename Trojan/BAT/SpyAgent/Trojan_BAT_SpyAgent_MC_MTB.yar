
rule Trojan_BAT_SpyAgent_MC_MTB{
	meta:
		description = "Trojan:BAT/SpyAgent.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0f 00 00 01 00 "
		
	strings :
		$a_00_0 = {fe 09 b9 05 1f 6d 2f 41 94 c5 5c cb eb fb 4e 68 41 38 8d 64 79 2d 3e 3a 38 bc 34 80 c1 e4 85 3a ad 7e 99 1d 5d cd 4c 0e 62 b8 5c b5 1b c3 c8 a7 } //01 00 
		$a_03_1 = {0c 08 02 16 02 8e 69 6f 90 01 03 0a 08 6f 90 01 03 0a 06 28 90 01 03 06 0d 28 90 01 03 06 09 2a 90 00 } //01 00 
		$a_81_2 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //01 00  RijndaelManaged
		$a_81_3 = {43 69 70 68 65 72 4d 6f 64 65 } //01 00  CipherMode
		$a_81_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_81_5 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00  TransformFinalBlock
		$a_81_6 = {47 65 74 42 79 74 65 73 } //01 00  GetBytes
		$a_81_7 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_81_8 = {53 74 72 52 65 76 65 72 73 65 } //01 00  StrReverse
		$a_81_9 = {56 69 72 74 75 61 6c } //01 00  Virtual
		$a_81_10 = {50 72 6f 74 65 63 74 } //01 00  Protect
		$a_81_11 = {46 72 6f 6d 42 61 73 65 36 34 } //01 00  FromBase64
		$a_81_12 = {73 65 74 5f 4b 65 79 } //01 00  set_Key
		$a_81_13 = {73 65 74 5f 55 73 65 4d 61 63 68 69 6e 65 4b 65 79 53 74 6f 72 65 } //01 00  set_UseMachineKeyStore
		$a_81_14 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //00 00  MemoryStream
	condition:
		any of ($a_*)
 
}