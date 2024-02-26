
rule Trojan_BAT_LokiBot_FK_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.FK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 09 00 00 0a 00 "
		
	strings :
		$a_01_0 = {57 b5 a2 3d 09 07 00 00 00 00 00 00 00 00 00 00 01 00 00 00 79 00 00 00 40 00 00 00 5c 00 00 00 36 01 00 00 56 } //01 00 
		$a_01_1 = {24 66 32 36 62 34 35 34 66 2d 39 37 34 35 2d 34 64 35 39 2d 39 30 64 34 2d 33 38 64 30 34 64 39 66 30 39 65 37 } //01 00  $f26b454f-9745-4d59-90d4-38d04d9f09e7
		$a_01_2 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //01 00  get_CurrentDomain
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00  DownloadData
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_5 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_01_6 = {52 65 76 65 72 73 65 } //01 00  Reverse
		$a_01_7 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_8 = {41 63 74 69 76 61 74 6f 72 } //00 00  Activator
	condition:
		any of ($a_*)
 
}