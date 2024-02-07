
rule Trojan_BAT_ArtemisMSILLoader_EM_MTB{
	meta:
		description = "Trojan:BAT/ArtemisMSILLoader.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 00 6c 00 65 00 61 00 6e 00 69 00 6e 00 67 00 2e 00 68 00 6f 00 6d 00 65 00 73 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 70 00 63 00 2e 00 63 00 6f 00 6d 00 2f 00 70 00 61 00 63 00 6b 00 61 00 67 00 65 00 73 00 } //01 00  cleaning.homesecuritypc.com/packages
		$a_01_1 = {57 65 62 52 65 71 75 65 73 74 } //01 00  WebRequest
		$a_01_2 = {4e 65 74 77 6f 72 6b 43 72 65 64 65 6e 74 69 61 6c } //01 00  NetworkCredential
		$a_01_3 = {57 65 62 48 65 61 64 65 72 43 6f 6c 6c 65 63 74 69 6f 6e } //01 00  WebHeaderCollection
		$a_01_4 = {43 6f 70 79 46 72 6f 6d 53 63 72 65 65 6e } //00 00  CopyFromScreen
	condition:
		any of ($a_*)
 
}