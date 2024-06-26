
rule Trojan_BAT_Polazert_DA_MTB{
	meta:
		description = "Trojan:BAT/Polazert.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 0d 00 00 28 00 "
		
	strings :
		$a_01_0 = {57 1f a2 1d 09 02 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 47 00 00 00 13 00 00 00 36 01 00 00 } //28 00 
		$a_01_1 = {57 1f a2 1d 09 02 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 48 00 00 00 13 00 00 00 31 01 00 00 } //28 00 
		$a_01_2 = {57 1f a2 1d 09 02 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 47 00 00 00 13 00 00 00 35 01 00 00 } //01 00 
		$a_01_3 = {47 65 74 52 65 71 75 65 73 74 53 74 72 65 61 6d } //01 00  GetRequestStream
		$a_01_4 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //01 00  GetResponseStream
		$a_01_5 = {57 65 62 45 78 63 65 70 74 69 6f 6e } //01 00  WebException
		$a_01_6 = {46 72 6f 6d 58 6d 6c 53 74 72 69 6e 67 } //01 00  FromXmlString
		$a_01_7 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_01_8 = {67 65 74 5f 4d 61 63 68 69 6e 65 4e 61 6d 65 } //01 00  get_MachineName
		$a_01_9 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_10 = {51 75 65 75 65 55 73 65 72 57 6f 72 6b 49 74 65 6d } //01 00  QueueUserWorkItem
		$a_01_11 = {43 6f 6e 76 65 72 74 } //01 00  Convert
		$a_01_12 = {52 65 70 6c 61 63 65 } //00 00  Replace
	condition:
		any of ($a_*)
 
}