
rule Trojan_BAT_taskloader_NBL_MTB{
	meta:
		description = "Trojan:BAT/taskloader.NBL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {fe 0c 10 00 1e 64 61 fe 0e 10 00 fe 0c 10 00 fe 0c 02 00 58 fe 0e 10 00 fe 0c 10 00 fe 0c 10 00 1f 17 64 61 fe 0e 10 00 fe 0c 10 00 fe 0c 2e 00 58 fe 0e 10 00 fe 0c 10 00 fe 0c 10 00 1f 09 62 61 fe 0e 10 00 fe 0c 10 00 fe 0c 32 00 58 fe 0e 10 00 fe 0c 23 00 1b 62 fe 0c 02 00 58 fe 0c 02 00 61 fe 0c 10 00 59 fe 0e 10 00 fe 0c 10 00 } //01 00 
		$a_80_1 = {45 6e 63 72 79 70 74 53 69 6d 70 6c 65 53 74 72 69 6e 67 } //EncryptSimpleString  01 00 
		$a_80_2 = {44 65 63 72 79 70 74 53 69 6d 70 6c 65 53 74 72 69 6e 67 } //DecryptSimpleString  01 00 
		$a_80_3 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //DownloadFile  01 00 
		$a_80_4 = {42 65 67 69 6e 49 6e 76 6f 6b 65 } //BeginInvoke  00 00 
	condition:
		any of ($a_*)
 
}