
rule Trojan_BAT_Quasar_ZA_MTB{
	meta:
		description = "Trojan:BAT/Quasar.ZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 33 43 33 37 34 41 34 32 2d 42 41 45 34 2d 31 31 43 46 2d 42 46 37 44 2d 30 30 41 41 30 30 36 39 34 36 45 45 } //01 00  $3C374A42-BAE4-11CF-BF7D-00AA006946EE
		$a_01_1 = {44 65 66 6c 61 74 65 53 74 72 65 61 6d } //01 00  DeflateStream
		$a_01_2 = {47 61 74 65 77 61 79 49 50 41 64 64 72 65 73 73 49 6e 66 6f 72 6d 61 74 69 6f 6e 43 6f 6c 6c 65 63 74 69 6f 6e } //01 00  GatewayIPAddressInformationCollection
		$a_01_3 = {44 45 53 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //01 00  DESCryptoServiceProvider
		$a_01_4 = {52 53 41 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //01 00  RSACryptoServiceProvider
		$a_01_5 = {53 79 73 74 65 6d 2e 53 65 63 75 72 69 74 79 2e 43 72 79 70 74 6f 67 72 61 70 68 79 2e 58 35 30 39 43 65 72 74 69 66 69 63 61 74 65 73 } //01 00  System.Security.Cryptography.X509Certificates
		$a_01_6 = {43 6c 69 65 6e 74 2e 54 65 73 74 73 } //01 00  Client.Tests
		$a_01_7 = {00 63 6f 6d 70 49 42 4d 26 26 00 } //01 00 
		$a_01_8 = {52 66 63 32 38 39 38 44 65 72 69 76 65 42 79 74 65 73 } //01 00  Rfc2898DeriveBytes
		$a_01_9 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_10 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggerNonUserCodeAttribute
	condition:
		any of ($a_*)
 
}