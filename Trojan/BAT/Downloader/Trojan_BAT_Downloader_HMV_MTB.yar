
rule Trojan_BAT_Downloader_HMV_MTB{
	meta:
		description = "Trojan:BAT/Downloader.HMV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,33 00 33 00 08 00 00 0a 00 "
		
	strings :
		$a_01_0 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //0a 00 
		$a_01_1 = {47 65 74 54 79 70 65 } //0a 00 
		$a_01_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //0a 00 
		$a_01_3 = {52 65 70 6c 61 63 65 } //0a 00 
		$a_81_4 = {00 42 4e 5a 58 4e 42 5a 58 42 4e 5a 58 42 4e 5a 58 42 4e 58 00 } //01 00 
		$a_80_5 = {74 72 61 6e 73 66 65 72 2e 73 68 2f 67 65 74 2f 42 76 33 58 4b 52 2f 62 6c 61 68 64 67 64 73 67 68 2e 74 78 74 } //transfer.sh/get/Bv3XKR/blahdgdsgh.txt  01 00 
		$a_80_6 = {74 72 61 6e 73 66 65 72 2e 73 68 2f 67 65 74 2f 54 33 68 48 38 66 2f 74 68 65 6e 65 77 64 6c 6c 2e 74 78 74 } //transfer.sh/get/T3hH8f/thenewdll.txt  01 00 
		$a_80_7 = {74 72 61 6e 73 66 65 72 2e 73 68 2f 67 65 74 2f 59 48 71 70 57 57 2f 64 76 69 6b 6c 6c 2e 74 78 74 } //transfer.sh/get/YHqpWW/dvikll.txt  00 00 
	condition:
		any of ($a_*)
 
}