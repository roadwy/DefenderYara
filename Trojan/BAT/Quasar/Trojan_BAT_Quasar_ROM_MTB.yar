
rule Trojan_BAT_Quasar_ROM_MTB{
	meta:
		description = "Trojan:BAT/Quasar.ROM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {0a 0a 17 8d 01 00 00 01 0c 08 16 17 8d 14 00 00 01 0d 09 a2 08 0b } //01 00 
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 41 73 79 6e 63 44 61 74 61 } //01 00  DownloadAsyncData
		$a_01_2 = {66 00 69 00 6c 00 65 00 62 00 69 00 6e 00 2e 00 6e 00 65 00 74 00 } //00 00  filebin.net
	condition:
		any of ($a_*)
 
}