
rule Trojan_BAT_Kryptik_MF_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {34 63 64 65 35 35 66 64 2d 61 36 64 65 2d 34 32 38 66 2d 61 64 35 38 2d 34 61 38 33 36 64 39 65 36 35 37 31 } //01 00  4cde55fd-a6de-428f-ad58-4a836d9e6571
		$a_81_1 = {63 63 65 39 64 64 37 31 62 39 66 32 34 31 61 66 39 34 39 31 32 38 38 30 61 65 39 34 33 30 65 64 } //01 00  cce9dd71b9f241af94912880ae9430ed
		$a_81_2 = {4e 4f 4b 49 41 20 50 52 4f } //01 00  NOKIA PRO
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_4 = {43 6f 6e 74 61 69 6e 73 4b 65 79 } //01 00  ContainsKey
		$a_01_5 = {4e 65 78 74 42 79 74 65 73 } //01 00  NextBytes
		$a_01_6 = {47 65 74 53 74 72 69 6e 67 } //01 00  GetString
		$a_01_7 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_01_8 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_01_9 = {57 72 69 74 65 } //01 00  Write
		$a_01_10 = {47 65 74 44 61 74 61 } //00 00  GetData
	condition:
		any of ($a_*)
 
}