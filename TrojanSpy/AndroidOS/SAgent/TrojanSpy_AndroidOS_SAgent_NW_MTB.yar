
rule TrojanSpy_AndroidOS_SAgent_NW_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SAgent.NW!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 09 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 65 6e 64 57 69 6e 72 61 72 45 78 70 6c 6f 69 74 } //01 00  SendWinrarExploit
		$a_00_1 = {67 65 74 65 77 61 79 70 6f 72 74 2e 74 78 74 } //01 00  getewayport.txt
		$a_00_2 = {73 6d 62 6f 6d 62 65 72 } //01 00  smbomber
		$a_00_3 = {67 65 74 6c 61 73 74 73 6d 73 } //01 00  getlastsms
		$a_00_4 = {6e 65 74 2e 4c 79 64 69 61 54 65 61 6d 2e 6c 6f 63 6b 70 61 67 65 } //01 00  net.LydiaTeam.lockpage
		$a_00_5 = {68 69 64 65 61 70 70 } //01 00  hideapp
		$a_00_6 = {67 65 74 61 6c 6c 6d 65 73 73 61 67 65 } //01 00  getallmessage
		$a_00_7 = {67 65 74 63 6f 6e 74 61 63 74 } //01 00  getcontact
		$a_03_8 = {70 65 79 67 69 72 69 2d 31 35 61 2e 6d 6c 90 02 15 2e 70 68 70 90 00 } //00 00 
		$a_00_9 = {5d 04 00 00 49 } //ff 04 
	condition:
		any of ($a_*)
 
}