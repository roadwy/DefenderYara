
rule Trojan_BAT_Kugbot_A{
	meta:
		description = "Trojan:BAT/Kugbot.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 00 6e 00 69 00 66 00 66 00 5f 00 68 00 69 00 74 00 } //1 sniff_hit
		$a_01_1 = {41 47 42 6f 74 2e 61 70 70 2e 6d 61 6e 69 66 65 73 74 } //1 AGBot.app.manifest
		$a_01_2 = {61 00 63 00 74 00 69 00 6f 00 6e 00 3d 00 55 00 53 00 42 00 20 00 44 00 72 00 69 00 76 00 65 00 20 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 } //1 action=USB Drive explorer
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}