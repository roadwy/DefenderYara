
rule Trojan_BAT_AsyncRat_ME_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 73 3a 2f 2f 75 66 69 6c 65 2e 69 6f 2f 72 66 74 61 65 71 74 63 } //01 00  https://ufile.io/rftaeqtc
		$a_81_1 = {4a 4e 4b 4e 41 49 57 55 46 48 38 } //01 00  JNKNAIWUFH8
		$a_81_2 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_81_3 = {57 65 62 52 65 71 75 65 73 74 } //01 00  WebRequest
		$a_81_4 = {47 65 74 52 65 73 70 6f 6e 73 65 } //01 00  GetResponse
		$a_81_5 = {57 65 62 52 65 73 70 6f 6e 73 65 } //01 00  WebResponse
		$a_81_6 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_81_7 = {45 6e 63 6f 64 69 6e 67 } //01 00  Encoding
		$a_81_8 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_9 = {54 6f 41 72 72 61 79 } //00 00  ToArray
	condition:
		any of ($a_*)
 
}