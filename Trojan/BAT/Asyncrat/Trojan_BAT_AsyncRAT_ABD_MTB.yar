
rule Trojan_BAT_AsyncRAT_ABD_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.ABD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 06 07 90 0a 2c 00 72 b5 ?? ?? 70 72 92 ?? ?? 70 28 1a ?? ?? 06 28 31 ?? ?? 0a 0b 72 b2 ?? ?? 70 72 92 ?? ?? 70 28 ?? ?? ?? 06 28 31 } //5
		$a_03_1 = {02 08 28 38 ?? ?? 0a 28 39 ?? ?? 0a 03 08 03 6f 10 ?? ?? 0a 5d 17 58 28 38 ?? ?? 0a 28 39 ?? ?? 0a 59 13 04 06 11 04 } //5
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_01_2  & 1)*1) >=11
 
}