
rule Trojan_AndroidOS_Rootnik_C_xp{
	meta:
		description = "Trojan:AndroidOS/Rootnik.C!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {25 73 2f 66 69 6c 65 73 2f 25 73 25 64 2e 6a 61 72 } //01 00  %s/files/%s%d.jar
		$a_00_1 = {2f 73 79 65 74 6d 2f 6c 69 62 3a 2f 76 65 6e 64 6f 72 2f 6c 69 62 } //01 00  /syetm/lib:/vendor/lib
		$a_00_2 = {25 73 2f 25 73 25 64 2e 64 65 78 } //01 00  %s/%s%d.dex
		$a_00_3 = {6c 69 62 53 64 6b 49 6d 70 6f 72 74 2e 73 6f } //01 00  libSdkImport.so
		$a_00_4 = {66 67 20 70 61 74 68 3a 25 73 00 2f 73 79 73 74 65 6d } //00 00  杦瀠瑡㩨猥⼀祳瑳浥
	condition:
		any of ($a_*)
 
}