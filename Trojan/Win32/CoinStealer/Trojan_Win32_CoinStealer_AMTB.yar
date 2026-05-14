
rule Trojan_Win32_CoinStealer_AMTB{
	meta:
		description = "Trojan:Win32/CoinStealer!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {68 74 74 70 90 02 01 3a 2f 2f 61 70 69 2e 74 65 6c 65 67 72 61 6d 2e 6f 72 67 2f 62 6f 74 38 33 33 33 34 36 39 30 36 34 3a 41 41 48 48 34 61 48 33 78 4c 6b 6f 4b 76 56 52 7a 43 78 77 68 41 38 2d 72 78 35 51 34 51 4d 64 4e 52 45 2f 73 65 6e 64 4d 65 73 73 61 67 65 } //http�://api.telegram.org/bot8333469064:AAHH4aH3xLkoKvVRzCxwhA8-rx5Q4QMdNRE/sendMessage  1
		$a_80_1 = {6c 65 64 67 65 72 20 6c 69 76 65 } //ledger live  1
		$a_80_2 = {62 75 74 74 6f 6e 69 4c 6f 73 74 4d 79 } //buttoniLostMy  1
		$a_80_3 = {4c 65 64 67 65 72 41 70 70 4d 75 74 65 78 } //LedgerAppMutex  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}