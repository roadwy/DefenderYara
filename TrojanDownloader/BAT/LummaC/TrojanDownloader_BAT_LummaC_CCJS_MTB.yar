
rule TrojanDownloader_BAT_LummaC_CCJS_MTB{
	meta:
		description = "TrojanDownloader:BAT/LummaC.CCJS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 61 79 6c 6f 61 64 4d 61 6e 61 67 65 72 2b 3c 46 65 74 63 68 50 61 79 6c 6f 61 64 41 73 79 6e 63 3e } //5 PayloadManager+<FetchPayloadAsync>
		$a_01_1 = {50 61 79 6c 6f 61 64 4d 61 6e 61 67 65 72 2b 3c 46 65 74 63 68 50 61 79 6c 6f 61 64 46 72 6f 6d 46 69 6c 65 41 73 79 6e 63 3e } //1 PayloadManager+<FetchPayloadFromFileAsync>
		$a_01_2 = {50 61 79 6c 6f 61 64 4d 61 6e 61 67 65 72 2b 3c 46 65 74 63 68 50 61 79 6c 6f 61 64 46 72 6f 6d 4e 65 74 77 6f 72 6b 41 73 79 6e 63 3e } //1 PayloadManager+<FetchPayloadFromNetworkAsync>
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}