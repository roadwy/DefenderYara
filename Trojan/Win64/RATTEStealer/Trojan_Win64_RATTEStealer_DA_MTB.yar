
rule Trojan_Win64_RATTEStealer_DA_MTB{
	meta:
		description = "Trojan:Win64/RATTEStealer.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 41 54 54 45 2f 52 41 54 54 45 67 6f } //1 RATTE/RATTEgo
		$a_01_1 = {67 6f 72 69 6c 6c 61 2f 77 65 62 73 6f 63 6b 65 74 } //1 gorilla/websocket
		$a_01_2 = {6d 61 69 6e 2e 42 6f 74 54 6f 6b 65 6e } //1 main.BotToken
		$a_01_3 = {43 61 70 74 75 72 65 } //1 Capture
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}