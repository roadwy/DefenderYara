
rule Trojan_BAT_SpyNoon_ME_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 03 8e 69 0b 2b 0a 06 07 03 07 91 6f 90 01 03 0a 07 25 17 59 0b 16 fe 02 2d ec 06 6f 90 01 03 0a 28 90 01 03 2b 0c 08 2a 90 00 } //01 00 
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00  DownloadData
		$a_03_2 = {3a 00 2f 00 2f 00 76 00 69 00 74 00 72 00 69 00 66 00 72 00 69 00 67 00 30 00 2e 00 63 00 6f 00 6d 00 2f 00 90 02 60 2e 00 6a 00 70 00 67 00 90 00 } //01 00 
		$a_01_3 = {44 79 6e 61 6d 69 63 49 6e 76 6f 6b 65 } //01 00  DynamicInvoke
		$a_01_4 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_5 = {54 6f 41 72 72 61 79 } //00 00  ToArray
	condition:
		any of ($a_*)
 
}