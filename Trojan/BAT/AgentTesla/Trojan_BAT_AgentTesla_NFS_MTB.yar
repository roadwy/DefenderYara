
rule Trojan_BAT_AgentTesla_NFS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NFS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 39 32 38 30 32 38 63 63 2d 36 62 33 63 2d 34 39 36 31 2d 62 32 31 34 2d 33 61 61 38 36 36 62 31 39 36 65 39 } //01 00  $928028cc-6b3c-4961-b214-3aa866b196e9
		$a_01_1 = {47 65 74 44 6f 6d 61 69 6e } //01 00  GetDomain
		$a_01_2 = {47 65 74 50 69 78 65 6c } //01 00  GetPixel
		$a_01_3 = {43 6f 6c 6f 72 54 72 61 6e 73 6c 61 74 6f 72 } //01 00  ColorTranslator
		$a_01_4 = {54 6f 57 69 6e 33 32 } //01 00  ToWin32
		$a_01_5 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggerNonUserCodeAttribute
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NFS_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NFS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {48 34 73 49 41 41 41 41 41 41 41 45 41 4f 31 38 43 58 67 55 78 37 46 77 7a 63 7a 65 } //01 00  H4sIAAAAAAAEAO18CXgUx7Fwzcze
		$a_81_1 = {65 41 46 76 74 70 4c 4f 4e 51 68 6e 75 6f 6c 58 4a 75 78 4c 44 56 57 57 68 41 69 44 } //01 00  eAFvtpLONQhnuolXJuxLDVWWhAiD
		$a_81_2 = {35 49 79 68 58 52 6c 44 46 7a 71 48 76 6b 32 4d 4d 34 6f 70 7a 51 52 42 74 55 73 38 } //01 00  5IyhXRlDFzqHvk2MM4opzQRBtUs8
		$a_81_3 = {79 65 79 5a 7a 57 79 64 77 4b 53 46 4b 53 32 63 45 4d 55 35 31 42 46 64 53 36 4a 51 } //01 00  yeyZzWydwKSFKS2cEMU51BFdS6JQ
		$a_81_4 = {46 72 6f 6d 42 61 73 65 36 34 } //01 00  FromBase64
		$a_81_5 = {47 5a 69 70 53 74 72 65 61 6d } //01 00  GZipStream
		$a_81_6 = {45 57 2e 59 4b } //00 00  EW.YK
	condition:
		any of ($a_*)
 
}