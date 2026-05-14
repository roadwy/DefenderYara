
rule Trojan_BAT_CredentialStealer_AMTB{
	meta:
		description = "Trojan:BAT/CredentialStealer!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {25 50 72 6f 67 72 61 6d 2b 3c 50 72 6f 63 65 73 73 43 68 72 6f 6d 65 4c 6f 67 69 6e 44 61 74 61 3e } //%Program+<ProcessChromeLoginData>  1
		$a_80_1 = {43 68 72 6f 6d 65 43 72 65 64 65 6e 74 69 61 6c 53 74 65 61 6c 65 72 2e 70 64 62 } //ChromeCredentialStealer.pdb  1
		$a_80_2 = {50 72 6f 67 72 61 6d 2b 3c 53 65 6e 64 54 65 6c 65 67 72 61 6d 46 69 6c 65 3e } //Program+<SendTelegramFile>  1
		$a_80_3 = {43 68 72 6f 6d 65 43 72 65 64 65 6e 74 69 61 6c 53 74 65 61 6c 65 72 2e 64 6c 6c } //ChromeCredentialStealer.dll  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}