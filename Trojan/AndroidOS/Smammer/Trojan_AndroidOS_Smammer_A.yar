
rule Trojan_AndroidOS_Smammer_A{
	meta:
		description = "Trojan:AndroidOS/Smammer.A,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {62 67 00 0c 62 6c 61 63 6b 4e 75 6d 62 65 72 73 00 } //1
		$a_01_1 = {64 6f 77 6e 6c 6f 61 64 65 72 2f 53 6d 73 52 65 63 65 69 76 65 72 24 53 63 61 6e } //1 downloader/SmsReceiver$Scan
		$a_01_2 = {64 6f 77 6e 6c 6f 61 64 65 72 2f 41 70 70 44 6f 77 6e 6c 6f 61 64 65 72 41 63 74 69 76 69 74 79 } //1 downloader/AppDownloaderActivity
		$a_01_3 = {41 70 70 44 6f 77 6e 6c 6f 61 64 65 72 41 63 74 69 76 69 74 79 2e 6a 61 76 61 00 0b 43 6f 6e 66 69 67 2e 6a 61 76 61 } //1
		$a_01_4 = {e2 80 a1 d0 b0 d0 b3 d1 80 d1 83 d0 b7 d0 ba d0 b0 20 00 01 01 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}