
rule Trojan_BAT_Kryptik_ME_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 06 73 16 00 00 0a 72 90 01 03 70 28 90 01 03 0a 72 90 01 03 70 28 90 01 03 06 1f 64 73 90 01 03 0a 1f 10 6f 90 01 03 0a 28 90 01 03 06 72 90 01 02 00 70 28 90 01 03 06 28 90 01 03 06 17 73 90 01 03 0a 13 01 20 00 00 00 00 28 90 01 03 06 39 90 01 01 00 00 00 26 20 00 00 00 00 38 90 00 } //01 00 
		$a_01_1 = {47 65 74 42 79 74 65 73 } //01 00  GetBytes
		$a_01_2 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_01_3 = {49 6e 69 74 43 6f 6d 70 6f 73 65 72 } //01 00  InitComposer
		$a_01_4 = {41 77 61 6b 65 43 6f 6d 70 6f 73 65 72 } //01 00  AwakeComposer
		$a_01_5 = {49 6e 76 6f 6b 65 43 6f 6d 70 6f 73 65 72 } //01 00  InvokeComposer
		$a_01_6 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_7 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //01 00  CreateEncryptor
		$a_01_8 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_9 = {73 65 74 5f 55 73 65 4d 61 63 68 69 6e 65 4b 65 79 53 74 6f 72 65 } //01 00  set_UseMachineKeyStore
		$a_01_10 = {73 65 74 5f 4b 65 79 } //01 00  set_Key
		$a_01_11 = {73 65 74 5f 49 56 } //00 00  set_IV
	condition:
		any of ($a_*)
 
}