
rule Trojan_AndroidOS_EventBot_B_MTB{
	meta:
		description = "Trojan:AndroidOS/EventBot.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {62 6f 74 5d 20 5b 61 63 63 65 73 73 5d 20 6f 6e 41 63 63 65 73 73 69 62 69 6c 69 74 79 45 76 65 6e 74 46 69 72 65 64 } //01 00  bot] [access] onAccessibilityEventFired
		$a_00_1 = {67 61 74 65 5f 63 62 38 61 35 61 65 61 31 61 62 33 30 32 66 30 } //01 00  gate_cb8a5aea1ab302f0
		$a_00_2 = {63 6f 6d 2e 65 78 61 6d 70 6c 65 2e 65 76 65 6e 74 62 6f 74 } //01 00  com.example.eventbot
		$a_00_3 = {73 74 75 64 69 6f 6c 65 67 61 6c 65 62 61 73 69 6c 69 2e 63 6f 6d } //01 00  studiolegalebasili.com
		$a_00_4 = {66 75 6e 63 5d 20 5b 73 65 72 76 69 63 65 5d 20 6f 6e 53 74 61 72 74 43 6f 6d 6d 61 6e 64 } //01 00  func] [service] onStartCommand
		$a_00_5 = {63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 65 76 65 6e 74 62 6f 74 2f 72 65 63 76 50 75 73 68 4d 73 67 } //01 00  com/example/eventbot/recvPushMsg
		$a_00_6 = {4c 63 6f 6d 2f 6c 69 62 49 6e 74 65 72 66 61 63 65 24 69 6e 6a 65 63 74 45 76 65 6e 74 } //00 00  Lcom/libInterface$injectEvent
	condition:
		any of ($a_*)
 
}