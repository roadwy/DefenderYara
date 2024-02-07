
rule TrojanDownloader_Win32_Chindo_DEA_MTB{
	meta:
		description = "TrojanDownloader:Win32/Chindo.DEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_81_0 = {5f 47 69 66 52 65 63 6f 72 64 5f 4d 75 65 78 74 5f } //01 00  _GifRecord_Muext_
		$a_81_1 = {7a 61 66 65 61 66 5f 66 66 61 65 61 61 64 66 61 73 64 66 } //01 00  zafeaf_ffaeaadfasdf
		$a_81_2 = {6b 6a 66 61 68 73 66 38 69 68 39 39 39 } //00 00  kjfahsf8ih999
	condition:
		any of ($a_*)
 
}