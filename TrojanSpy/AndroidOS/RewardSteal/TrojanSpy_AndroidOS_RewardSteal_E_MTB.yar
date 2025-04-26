
rule TrojanSpy_AndroidOS_RewardSteal_E_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/RewardSteal.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {61 64 70 74 65 72 5f 67 65 74 75 73 65 74 } //1 adpter_getuset
		$a_00_1 = {73 65 6e 64 65 72 4e 6f 74 69 } //1 senderNoti
		$a_00_2 = {73 65 72 76 65 72 5f 64 6f 77 6e } //1 server_down
		$a_00_3 = {64 69 76 69 63 65 62 6c 6f 63 6b } //1 diviceblock
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}