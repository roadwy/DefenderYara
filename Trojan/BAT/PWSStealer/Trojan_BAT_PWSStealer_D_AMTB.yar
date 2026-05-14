
rule Trojan_BAT_PWSStealer_D_AMTB{
	meta:
		description = "Trojan:BAT/PWSStealer.D!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {53 65 6e 64 54 65 6c 65 67 72 61 6d 4d 65 73 73 61 67 65 } //1 SendTelegramMessage
		$a_81_1 = {47 65 74 44 69 73 63 6f 72 64 54 6f 6b 65 6e 73 } //1 GetDiscordTokens
		$a_81_2 = {3c 41 6e 74 69 56 4d 3e } //1 <AntiVM>
		$a_81_3 = {62 6f 74 54 6f 6b 65 6e } //1 botToken
		$a_81_4 = {3c 53 65 6e 64 44 61 74 61 73 3e } //1 <SendDatas>
		$a_81_5 = {4b 69 6c 6c 56 50 4e 73 } //1 KillVPNs
		$a_81_6 = {53 74 65 61 6c 65 72 } //2 Stealer
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*2) >=7
 
}