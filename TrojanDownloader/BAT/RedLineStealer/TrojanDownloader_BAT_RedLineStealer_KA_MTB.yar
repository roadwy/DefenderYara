
rule TrojanDownloader_BAT_RedLineStealer_KA_MTB{
	meta:
		description = "TrojanDownloader:BAT/RedLineStealer.KA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {04 8e 69 28 ?? ?? ?? 0a 00 28 ?? ?? ?? 0a 7e ?? ?? ?? 04 6f ?? ?? ?? 0a 26 00 2a 90 0a 26 00 7e ?? ?? ?? 04 16 7e } //1
		$a_01_1 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //1 GetResponseStream
		$a_01_2 = {47 65 74 52 65 73 70 6f 6e 73 65 } //1 GetResponse
		$a_01_3 = {52 65 61 64 42 79 74 65 73 } //1 ReadBytes
		$a_01_4 = {57 65 62 52 65 71 75 65 73 74 } //1 WebRequest
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}