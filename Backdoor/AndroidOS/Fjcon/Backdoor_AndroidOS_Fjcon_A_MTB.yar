
rule Backdoor_AndroidOS_Fjcon_A_MTB{
	meta:
		description = "Backdoor:AndroidOS/Fjcon.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {67 65 74 53 65 6e 64 6d 73 67 } //01 00  getSendmsg
		$a_00_1 = {73 65 6e 64 53 4d 53 42 79 50 6c 61 74 66 6f 72 6d } //01 00  sendSMSByPlatform
		$a_00_2 = {67 65 74 53 4d 53 43 6f 6e 74 65 6e 74 } //01 00  getSMSContent
		$a_00_3 = {67 65 74 50 68 6f 6e 65 46 72 6f 6d 55 52 4c } //01 00  getPhoneFromURL
		$a_00_4 = {65 6e 63 6f 64 65 53 6d 73 } //01 00  encodeSms
		$a_00_5 = {64 69 61 6c 50 68 6f 6e 65 42 79 50 6c 61 74 66 6f 72 6d } //00 00  dialPhoneByPlatform
	condition:
		any of ($a_*)
 
}