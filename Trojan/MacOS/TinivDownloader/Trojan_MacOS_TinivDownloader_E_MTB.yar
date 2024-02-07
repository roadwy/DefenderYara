
rule Trojan_MacOS_TinivDownloader_E_MTB{
	meta:
		description = "Trojan:MacOS/TinivDownloader.E!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {69 70 68 6f 6e 65 6f 73 2f 7a 68 65 6e 67 2e 62 75 69 6c 64 } //01 00  iphoneos/zheng.build
		$a_01_1 = {61 70 69 2e 36 74 61 2e 63 6f 2f 6b 69 6c 6c 6d 2e 70 68 70 } //01 00  api.6ta.co/killm.php
		$a_00_2 = {35 52 4e 33 57 4d 4c 53 4c 45 } //01 00  5RN3WMLSLE
		$a_00_3 = {42 36 37 4c 54 4c 41 4e 35 53 } //00 00  B67LTLAN5S
	condition:
		any of ($a_*)
 
}