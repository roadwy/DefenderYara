
rule HackTool_AndroidOS_Penetrate_A_xp{
	meta:
		description = "HackTool:AndroidOS/Penetrate.A!xp,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 74 68 6f 6d 73 6f 6e 2f 74 68 6f 6d 73 6f 6e 2e 7a 69 70 } //01 00  /thomson/thomson.zip
		$a_00_1 = {3a 2f 2f 70 65 6e 65 74 72 61 74 65 2e 75 6e 64 65 72 64 65 76 2e 6f 72 67 2f 73 2f 74 68 6f 6d 73 6f 6e 2e 73 65 72 76 69 63 65 2e 70 68 70 3f 69 64 3d } //01 00  ://penetrate.underdev.org/s/thomson.service.php?id=
		$a_00_2 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 54 61 73 6b 2e 6a 61 76 61 } //01 00  DownloadFileTask.java
		$a_00_3 = {70 65 6e 65 74 72 61 74 65 2f 6c 69 62 2f 63 6f 72 65 2f 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 54 61 73 6b 24 31 } //00 00  penetrate/lib/core/DownloadFileTask$1
		$a_00_4 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}