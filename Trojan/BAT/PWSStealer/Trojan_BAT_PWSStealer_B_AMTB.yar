
rule Trojan_BAT_PWSStealer_B_AMTB{
	meta:
		description = "Trojan:BAT/PWSStealer.B!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_81_0 = {44 49 53 43 4f 52 44 20 53 54 45 41 4c 45 52 20 45 58 45 43 55 54 45 44 } //1 DISCORD STEALER EXECUTED
		$a_81_1 = {41 64 76 61 6e 63 65 64 44 69 73 63 6f 72 64 53 74 65 61 6c 65 72 } //1 AdvancedDiscordStealer
		$a_81_2 = {42 6f 74 54 6f 6b 65 6e } //1 BotToken
		$a_81_3 = {53 65 6e 64 54 6f 54 65 6c 65 67 72 61 6d } //1 SendToTelegram
		$a_81_4 = {73 74 65 61 6c 65 72 2e 65 78 65 } //1 stealer.exe
		$a_81_5 = {73 74 65 61 6c 65 72 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 73 74 65 61 6c 65 72 2e 70 64 62 } //2 stealer\obj\Release\stealer.pdb
		$a_81_6 = {53 74 65 61 6c 65 72 2e 50 72 6f 67 72 61 6d } //1 Stealer.Program
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*2+(#a_81_6  & 1)*1) >=5
 
}