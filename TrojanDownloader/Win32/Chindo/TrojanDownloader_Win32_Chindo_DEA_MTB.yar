
rule TrojanDownloader_Win32_Chindo_DEA_MTB{
	meta:
		description = "TrojanDownloader:Win32/Chindo.DEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {5f 47 69 66 52 65 63 6f 72 64 5f 4d 75 65 78 74 5f } //1 _GifRecord_Muext_
		$a_81_1 = {7a 61 66 65 61 66 5f 66 66 61 65 61 61 64 66 61 73 64 66 } //1 zafeaf_ffaeaadfasdf
		$a_81_2 = {6b 6a 66 61 68 73 66 38 69 68 39 39 39 } //1 kjfahsf8ih999
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}