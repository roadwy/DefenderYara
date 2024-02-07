
rule Trojan_BAT_Perseus_XB_MTB{
	meta:
		description = "Trojan:BAT/Perseus.XB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 6f 73 74 75 72 61 2e 68 74 74 70 2e 69 6e 66 2e 64 6c 6c 2e 7a 69 70 } //01 00  costura.http.inf.dll.zip
		$a_00_1 = {63 6f 73 74 75 72 61 2e 68 74 74 70 2e 69 6e 66 2e 70 64 62 2e 7a 69 70 } //01 00  costura.http.inf.pdb.zip
		$a_00_2 = {49 00 73 00 44 00 65 00 62 00 75 00 67 00 67 00 65 00 72 00 50 00 72 00 65 00 73 00 65 00 6e 00 74 00 } //01 00  IsDebuggerPresent
		$a_00_3 = {62 79 74 65 73 54 6f 44 65 63 6f 6d 70 72 65 73 73 } //01 00  bytesToDecompress
		$a_00_4 = {44 65 63 6f 6d 70 72 65 73 73 47 5a 69 70 } //01 00  DecompressGZip
		$a_03_5 = {53 65 74 74 69 6e 67 73 90 02 0f 74 74 00 42 79 74 65 00 75 6b 6b 90 00 } //00 00 
		$a_00_6 = {5d 04 00 00 } //9c 58 
	condition:
		any of ($a_*)
 
}