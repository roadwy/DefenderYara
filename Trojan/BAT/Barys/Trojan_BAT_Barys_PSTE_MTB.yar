
rule Trojan_BAT_Barys_PSTE_MTB{
	meta:
		description = "Trojan:BAT/Barys.PSTE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 01 00 "
		
	strings :
		$a_01_0 = {36 46 44 43 31 44 42 44 } //01 00  6FDC1DBD
		$a_01_1 = {32 33 36 45 37 38 34 44 } //01 00  236E784D
		$a_01_2 = {34 43 30 36 30 44 34 39 } //01 00  4C060D49
		$a_01_3 = {33 39 45 38 33 31 43 36 } //01 00  39E831C6
		$a_01_4 = {32 34 32 43 30 35 36 42 } //01 00  242C056B
		$a_01_5 = {32 35 30 34 37 36 32 39 } //01 00  25047629
		$a_01_6 = {43 6f 6d 70 75 74 65 48 61 73 68 } //01 00  ComputeHash
		$a_01_7 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //01 00  DownloadString
		$a_01_8 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_9 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //01 00  GetExecutingAssembly
		$a_01_10 = {57 72 69 74 65 49 6e 74 36 34 } //01 00  WriteInt64
		$a_01_11 = {67 65 74 5f 55 54 46 38 } //01 00  get_UTF8
		$a_01_12 = {42 6c 6f 63 6b 43 6f 70 79 } //00 00  BlockCopy
	condition:
		any of ($a_*)
 
}