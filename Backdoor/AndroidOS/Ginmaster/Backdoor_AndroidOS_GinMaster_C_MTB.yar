
rule Backdoor_AndroidOS_GinMaster_C_MTB{
	meta:
		description = "Backdoor:AndroidOS/GinMaster.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {21 12 35 20 0c 00 48 02 01 00 df 02 02 18 8d 22 4f 02 01 00 d8 00 00 01 28 f4 } //3
		$a_01_1 = {63 6f 6d 2e 67 61 6d 65 73 6e 73 } //1 com.gamesns
		$a_01_2 = {47 6c 6f 66 74 53 45 54 54 } //1 GloftSETT
		$a_01_3 = {6d 70 53 65 6e 64 47 65 74 50 6c 61 79 65 72 44 61 74 61 } //1 mpSendGetPlayerData
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}