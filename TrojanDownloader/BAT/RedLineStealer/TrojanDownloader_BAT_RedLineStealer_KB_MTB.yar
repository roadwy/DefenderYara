
rule TrojanDownloader_BAT_RedLineStealer_KB_MTB{
	meta:
		description = "TrojanDownloader:BAT/RedLineStealer.KB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {0a 00 08 6f ?? ?? ?? 0a 00 16 2d ?? 06 08 6f ?? ?? ?? 0a 16 08 6f ?? ?? ?? 0a 8e 69 6f ?? ?? ?? 0a 00 06 0d 90 0a 46 00 72 ?? ?? ?? 70 2b ?? 2b ?? 2b ?? 2b ?? 20 ?? ?? ?? 05 2b ?? 2b ?? 73 ?? ?? ?? 0a 0c 08 07 6f } //1
		$a_01_1 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //1 GetResponseStream
		$a_01_2 = {47 65 74 52 65 73 70 6f 6e 73 65 } //1 GetResponse
		$a_01_3 = {52 65 61 64 42 79 74 65 73 } //1 ReadBytes
		$a_01_4 = {57 65 62 52 65 71 75 65 73 74 } //1 WebRequest
		$a_01_5 = {57 65 62 52 65 73 70 6f 6e 73 65 } //1 WebResponse
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}