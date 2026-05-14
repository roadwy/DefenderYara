
rule TrojanDownloader_MacOS_SAgnt_HAB_MTB{
	meta:
		description = "TrojanDownloader:MacOS/SAgnt.HAB!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,10 00 10 00 03 00 00 "
		
	strings :
		$a_03_0 = {68 74 74 70 73 3a 2f 2f [0-10] 2e 73 70 61 63 65 2f 63 75 72 6c 2f } //5
		$a_01_1 = {2d 77 20 22 25 7b 68 74 74 70 5f 63 6f 64 65 7d 22 20 22 24 } //1 -w "%{http_code}" "$
		$a_03_2 = {2f 4c 69 62 72 61 72 79 2f 41 70 70 6c 69 63 61 74 69 6f 6e 20 53 75 70 70 6f 72 74 2f [0-10] 00 00 00 00 [0-10] 2f 4c 69 62 72 61 72 79 2f 4c 6f 67 73 2f 90 1b 00 2e 6c 6f 67 } //10
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_03_2  & 1)*10) >=16
 
}