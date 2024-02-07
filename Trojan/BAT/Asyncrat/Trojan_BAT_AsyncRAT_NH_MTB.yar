
rule Trojan_BAT_AsyncRAT_NH_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.NH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {2b 00 16 2d f8 16 2d d0 2a 28 90 01 03 0a 2b cf 03 2b ce 28 90 01 03 0a 2b ce 6f 90 01 03 0a 2b cf 28 90 01 03 0a 2b ca 28 90 01 03 0a 2b ce 90 00 } //01 00 
		$a_01_1 = {54 6f 49 6e 74 33 32 } //01 00  ToInt32
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00  DownloadData
		$a_01_3 = {44 79 6e 61 6d 69 63 49 6e 76 6f 6b 65 } //00 00  DynamicInvoke
	condition:
		any of ($a_*)
 
}