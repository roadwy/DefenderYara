
rule TrojanDownloader_BAT_QuasarRAT_SS_MTB{
	meta:
		description = "TrojanDownloader:BAT/QuasarRAT.SS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {24 63 63 37 66 61 64 30 33 2d 38 31 36 65 2d 34 33 32 63 2d 39 62 39 32 2d 30 30 31 66 32 64 33 37 38 34 39 38 } //1 $cc7fad03-816e-432c-9b92-001f2d378498
		$a_81_1 = {73 65 72 76 65 72 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 server.Resources.resources
		$a_81_2 = {46 61 69 6c 46 61 73 74 } //1 FailFast
		$a_81_3 = {49 6e 76 6f 6b 65 } //1 Invoke
		$a_81_4 = {47 65 74 42 79 74 65 73 } //1 GetBytes
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}