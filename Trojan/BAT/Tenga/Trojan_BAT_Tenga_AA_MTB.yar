
rule Trojan_BAT_Tenga_AA_MTB{
	meta:
		description = "Trojan:BAT/Tenga.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 74 74 70 57 65 62 52 65 73 70 6f 6e 73 65 } //01 00  HttpWebResponse
		$a_00_1 = {57 65 62 48 65 61 64 65 72 43 6f 6c 6c 65 63 74 69 6f 6e } //01 00  WebHeaderCollection
		$a_81_2 = {3c 6d 65 74 61 20 6e 61 6d 65 3d 22 6b 65 79 77 6f 72 64 73 22 20 63 6f 6e 74 65 6e 74 3d 22 28 5b 5c 77 5c 64 20 5d 2a 29 22 3e } //01 00  <meta name="keywords" content="([\w\d ]*)">
		$a_81_3 = {61 70 64 6f 63 72 6f 74 6f 2e 67 71 } //00 00  apdocroto.gq
	condition:
		any of ($a_*)
 
}