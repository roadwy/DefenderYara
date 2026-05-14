
rule Trojan_BAT_UltimateStealer_AMTB{
	meta:
		description = "Trojan:BAT/UltimateStealer!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {55 6c 74 69 6d 61 74 65 53 74 65 61 6c 65 72 2e 50 72 6f 67 72 61 6d 2b 3c 43 68 65 63 6b 4c 69 76 65 42 61 6e 6b 53 65 73 73 69 6f 6e 73 3e } //UltimateStealer.Program+<CheckLiveBankSessions>  1
		$a_80_1 = {55 6c 74 69 6d 61 74 65 53 74 65 61 6c 65 72 2e 50 72 6f 67 72 61 6d 2b 3c 53 65 6e 64 50 68 69 73 68 69 6e 67 4c 69 6e 6b 3e } //UltimateStealer.Program+<SendPhishingLink>  1
		$a_80_2 = {55 6c 74 69 6d 61 74 65 53 74 65 61 6c 65 72 2e 50 72 6f 67 72 61 6d 2b 3c 53 74 65 61 6c 54 4f 4e 57 61 6c 6c 65 74 3e } //UltimateStealer.Program+<StealTONWallet>  1
		$a_80_3 = {55 6c 74 69 6d 61 74 65 53 74 65 61 6c 65 72 2e 50 72 6f 67 72 61 6d 2b 3c 53 74 65 61 6c 44 65 73 6b 74 6f 70 57 61 6c 6c 65 74 73 3e } //UltimateStealer.Program+<StealDesktopWallets>  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}