
rule TrojanDropper_AndroidOS_GhostCtrl_A_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/GhostCtrl.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 61 6e 64 72 6f 69 64 2e 65 6e 67 69 6e 65 2e 61 70 6b } //01 00  /android.engine.apk
		$a_01_1 = {44 49 52 45 43 54 4f 52 59 5f 44 4f 57 4e 4c 4f 41 44 53 } //01 00  DIRECTORY_DOWNLOADS
		$a_00_2 = {2f 63 6f 6e 74 65 6e 74 2f 43 6f 6d 70 6f 6e 65 6e 74 4e 61 6d 65 } //01 00  /content/ComponentName
		$a_00_3 = {41 70 70 6c 69 63 61 74 69 6f 6e 20 69 73 20 6e 6f 74 20 63 6f 6d 70 61 74 69 62 6c 65 20 77 69 74 68 20 79 6f 75 72 20 61 6e 64 72 6f 69 64 20 76 65 72 73 69 6f 6e } //00 00  Application is not compatible with your android version
	condition:
		any of ($a_*)
 
}