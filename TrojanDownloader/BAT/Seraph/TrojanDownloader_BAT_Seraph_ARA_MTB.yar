
rule TrojanDownloader_BAT_Seraph_ARA_MTB{
	meta:
		description = "TrojanDownloader:BAT/Seraph.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00  InvokeMember
		$a_01_1 = {57 65 62 52 65 73 70 6f 6e 73 65 } //01 00  WebResponse
		$a_01_2 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //02 00  GetResponseStream
		$a_01_3 = {09 11 04 08 11 04 08 8e 69 5d 91 06 11 04 91 61 d2 9c 11 04 17 58 13 04 11 04 06 8e 69 32 e1 } //00 00 
	condition:
		any of ($a_*)
 
}