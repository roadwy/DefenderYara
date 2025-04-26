
rule Trojan_BAT_AsyncRAT_ABK_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.ABK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_03_0 = {0a 06 06 28 ?? ?? ?? 0a 0a 72 ?? ?? ?? 70 0b 72 ?? ?? ?? 70 25 28 ?? ?? ?? 0a 26 72 ?? ?? ?? 70 0c 72 ?? ?? ?? 70 0d 06 06 28 ?? ?? ?? 0a 0d 09 28 ?? ?? ?? 0a 09 09 28 ?? ?? ?? 0a 0d 72 ?? ?? ?? 70 13 04 } //5
		$a_01_1 = {48 74 74 70 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 HttpDownloadFile
		$a_01_2 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //1 GetResponseStream
		$a_01_3 = {44 65 6c 65 74 65 44 69 72 65 63 74 6f 72 79 } //1 DeleteDirectory
		$a_01_4 = {70 00 6f 00 77 00 65 00 72 00 6d 00 6f 00 6e 00 73 00 74 00 65 00 72 00 } //1 powermonster
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=9
 
}