
rule Trojan_BAT_Downloader_BGF_MTB{
	meta:
		description = "Trojan:BAT/Downloader.BGF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_81_0 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_1 = {4e 65 77 4d 65 74 68 6f 64 65 } //01 00  NewMethode
		$a_81_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_81_3 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_81_4 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00  TransformFinalBlock
		$a_81_5 = {49 6e 76 6f 6b 65 } //01 00  Invoke
		$a_81_6 = {50 61 73 73 } //01 00  Pass
		$a_81_7 = {59 79 79 79 } //01 00  Yyyy
		$a_81_8 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //01 00  GetExecutingAssembly
		$a_81_9 = {47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 53 74 72 65 61 6d } //00 00  GetManifestResourceStream
	condition:
		any of ($a_*)
 
}