
rule TrojanSpy_AndroidOS_Dabom_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Dabom.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0b 00 0b 00 04 00 00 05 00 "
		
	strings :
		$a_00_0 = {73 65 6e 64 5f 6d 65 73 73 61 67 65 5f 63 6f 6e 74 65 63 74 } //05 00  send_message_contect
		$a_00_1 = {73 6d 73 62 6f 6d 62 65 72 } //01 00  smsbomber
		$a_00_2 = {67 65 74 4e 65 74 77 6f 72 6b 53 65 63 75 72 69 74 79 43 6f 6e 66 69 67 } //01 00  getNetworkSecurityConfig
		$a_00_3 = {75 6e 68 69 64 65 61 6c 6c } //00 00  unhideall
	condition:
		any of ($a_*)
 
}