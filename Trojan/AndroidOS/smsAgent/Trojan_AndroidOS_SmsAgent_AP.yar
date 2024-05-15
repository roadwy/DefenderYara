
rule Trojan_AndroidOS_SmsAgent_AP{
	meta:
		description = "Trojan:AndroidOS/SmsAgent.AP,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 03 00 00 03 00 "
		
	strings :
		$a_01_0 = {65 78 61 6d 70 6c 65 2f 61 70 70 6a 61 76 61 2f 52 65 63 65 69 76 65 53 6d 73 } //01 00  example/appjava/ReceiveSms
		$a_01_1 = {26 74 65 78 74 3d 2a 4e 65 77 20 53 4d 53 20 4e 67 61 6e 20 4c 61 6a 75 2a 20 25 30 41 25 30 41 2a 53 65 6e 64 65 72 20 2a 20 3a 20 5f } //01 00  &text=*New SMS Ngan Laju* %0A%0A*Sender * : _
		$a_01_2 = {5f 25 30 41 25 30 41 2a 54 79 70 65 20 50 65 72 61 6e 67 6b 61 74 20 3a 20 2a } //00 00  _%0A%0A*Type Perangkat : *
	condition:
		any of ($a_*)
 
}