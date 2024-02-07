
rule Trojan_AndroidOS_SpyAgent_E_MTB{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2f 73 71 69 73 6c 61 6e 64 2f 61 6e 64 72 6f 69 64 2f 73 77 69 70 65 5f 69 6d 61 67 65 5f 76 69 65 77 65 72 } //01 00  com/sqisland/android/swipe_image_viewer
		$a_00_1 = {53 65 6e 64 48 65 6c 6c 6f 50 61 63 6b 65 74 } //01 00  SendHelloPacket
		$a_00_2 = {67 65 74 41 6c 6c 46 69 6c 65 73 4f 66 44 69 72 55 70 6c 6f 61 64 54 6f 4c 69 76 65 } //00 00  getAllFilesOfDirUploadToLive
	condition:
		any of ($a_*)
 
}