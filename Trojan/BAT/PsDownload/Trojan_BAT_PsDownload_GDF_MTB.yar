
rule Trojan_BAT_PsDownload_GDF_MTB{
	meta:
		description = "Trojan:BAT/PsDownload.GDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {09 06 11 04 06 8e 69 5d 91 08 11 04 91 61 d2 6f 90 01 03 0a 11 04 17 58 13 04 11 04 08 8e 69 32 df 90 00 } //10
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_2 = {44 79 6e 61 6d 69 63 49 6e 76 6f 6b 65 } //1 DynamicInvoke
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}