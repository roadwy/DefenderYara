
rule Trojan_BAT_ZgRAT_KAD_MTB{
	meta:
		description = "Trojan:BAT/ZgRAT.KAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 31 00 71 00 77 00 71 00 65 00 77 00 72 00 65 00 77 00 71 00 77 00 65 00 71 00 77 00 72 00 71 00 65 00 2e 00 73 00 62 00 73 00 } //01 00  http://1qwqewrewqweqwrqe.sbs
		$a_01_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 62 00 63 00 6d 00 6e 00 75 00 72 00 73 00 69 00 6e 00 67 00 2e 00 63 00 6f 00 6d 00 } //01 00  http://www.bcmnursing.com
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //00 00  DownloadFile
	condition:
		any of ($a_*)
 
}