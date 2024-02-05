
rule TrojanDownloader_MacOS_Shlayer_E_MTB{
	meta:
		description = "TrojanDownloader:MacOS/Shlayer.E!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6f 72 67 2e 77 30 6c 66 2e 63 44 6f 63 6b 48 65 6c 70 65 72 } //01 00 
		$a_01_1 = {69 6d 70 6f 72 74 20 63 6f 6d 2e 61 70 70 6c 65 2e 64 6f 63 6b 20 2f 74 6d 70 2f 64 6f 63 6b 2e 70 6c 69 73 74 } //01 00 
		$a_01_2 = {2f 74 6d 70 2f 64 6d 69 6e 73 74 } //01 00 
		$a_01_3 = {73 6c 65 65 70 20 25 6c 75 3b 20 6f 70 65 6e 20 22 25 40 22 } //01 00 
		$a_01_4 = {63 6f 6d 2e 64 6f 63 6b 32 6d 61 73 74 65 72 2e 44 6f 63 6b 32 4d 61 73 74 65 72 48 65 6c 70 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}