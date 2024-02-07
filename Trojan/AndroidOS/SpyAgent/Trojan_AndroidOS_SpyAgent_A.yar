
rule Trojan_AndroidOS_SpyAgent_A{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.A,SIGNATURE_TYPE_DEXHSTR_EXT,0f 00 0f 00 05 00 00 05 00 "
		
	strings :
		$a_00_0 = {75 72 6c 5f 74 65 6c 65 67 72 61 6d 5f 72 65 64 69 72 65 63 74 } //05 00  url_telegram_redirect
		$a_00_1 = {73 65 6e 64 5f 6d 65 73 73 61 67 65 } //05 00  send_message
		$a_00_2 = {68 69 64 64 65 6e 5f 61 70 70 } //05 00  hidden_app
		$a_00_3 = {73 65 6e 64 65 72 5f 74 68 72 65 61 64 65 72 } //05 00  sender_threader
		$a_00_4 = {4e 65 77 20 44 65 76 69 63 65 20 4f 70 65 6e 65 64 20 41 70 70 6c 69 63 61 74 69 6f 6e 3a } //00 00  New Device Opened Application:
	condition:
		any of ($a_*)
 
}