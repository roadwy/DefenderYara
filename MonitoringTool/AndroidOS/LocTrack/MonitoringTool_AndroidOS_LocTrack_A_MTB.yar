
rule MonitoringTool_AndroidOS_LocTrack_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/LocTrack.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {4c 63 6f 6d 2f 61 76 2f 72 72 67 64 66 67 64 67 2f 66 69 6e 64 65 72 } //01 00  Lcom/av/rrgdfgdg/finder
		$a_01_1 = {4c 6f 63 61 74 69 6f 6e 4c 69 73 74 65 6e 65 72 } //01 00  LocationListener
		$a_01_2 = {68 69 64 65 4f 6e 43 6f 6e 74 65 6e 74 53 63 72 6f 6c 6c } //01 00  hideOnContentScroll
		$a_01_3 = {6f 6e 54 61 73 6b 52 65 6d 6f 76 65 64 } //01 00  onTaskRemoved
		$a_01_4 = {4c 63 6f 6d 2f 61 76 2f 64 61 76 69 64 2f 66 69 6e 64 65 72 2f 53 65 6e 64 5f 74 6f } //00 00  Lcom/av/david/finder/Send_to
	condition:
		any of ($a_*)
 
}