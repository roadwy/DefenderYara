
rule TrojanSpy_AndroidOS_Knbot_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Knbot.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {66 72 65 65 2e 7a 77 69 66 69 70 72 6f 2e 63 6f 6d 2f 67 61 74 65 } //1 free.zwifipro.com/gate
		$a_01_1 = {70 75 62 2e 7a 77 69 66 69 2e 70 72 6f } //1 pub.zwifi.pro
		$a_00_2 = {66 75 6e 63 5d 20 5b 6d 73 67 5d 20 5b 72 65 63 76 50 75 73 68 4d 73 67 5d 20 5b 6f 6e 52 65 63 65 69 76 65 } //1 func] [msg] [recvPushMsg] [onReceive
		$a_01_3 = {65 76 65 6e 74 42 6f 74 } //1 eventBot
		$a_01_4 = {67 61 74 65 5f 63 62 38 61 35 61 65 61 31 61 62 33 30 32 66 30 5f 63 } //1 gate_cb8a5aea1ab302f0_c
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}