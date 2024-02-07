
rule TrojanDownloader_MacOS_Keydnap_B_MTB{
	meta:
		description = "TrojanDownloader:MacOS/Keydnap.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {2f 74 6d 70 2f 63 6f 6d 2e 61 70 70 6c 65 2e 69 63 6c 6f 75 64 73 79 6e 63 64 } //01 00  /tmp/com.apple.icloudsyncd
		$a_01_1 = {6b 69 6c 6c 61 6c 6c 20 54 65 72 6d 69 6e 61 6c } //01 00  killall Terminal
		$a_01_2 = {65 6c 69 74 65 66 75 63 6b } //01 00  elitefuck
		$a_01_3 = {5f 63 72 65 61 74 65 44 61 65 6d 6f 6e } //00 00  _createDaemon
		$a_00_4 = {5d 04 00 } //00 02 
	condition:
		any of ($a_*)
 
}