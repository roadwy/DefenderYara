
rule Trojan_BAT_AveMariaRat_MT_MTB{
	meta:
		description = "Trojan:BAT/AveMariaRat.MT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 0a 00 00 0a 00 "
		
	strings :
		$a_01_0 = {73 00 63 00 76 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //01 00  scvhost.exe
		$a_01_1 = {73 00 73 00 64 00 64 00 66 00 64 00 61 00 73 00 64 00 66 00 66 00 66 00 66 00 66 00 66 00 66 00 66 00 66 00 66 00 66 00 66 00 66 00 66 00 66 00 66 00 66 00 66 00 64 00 64 00 64 00 } //01 00  ssddfdasdffffffffffffffffffddd
		$a_01_2 = {52 65 76 65 72 73 65 } //01 00  Reverse
		$a_01_3 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  ToBase64String
		$a_01_4 = {44 65 62 75 67 67 65 72 4c 61 75 6e 63 68 65 64 } //01 00  DebuggerLaunched
		$a_01_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_6 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00  TransformFinalBlock
		$a_01_7 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_8 = {47 65 74 42 79 74 65 73 } //01 00  GetBytes
		$a_01_9 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00  FromBase64String
	condition:
		any of ($a_*)
 
}