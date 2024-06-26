
rule Trojan_BAT_CryptInject_PM_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.PM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0d 09 09 47 02 08 1f 90 01 01 5d 91 61 d2 52 00 08 17 d6 0c 08 07 fe 90 01 01 16 fe 90 01 01 13 90 01 01 11 90 01 01 2d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_CryptInject_PM_MTB_2{
	meta:
		description = "Trojan:BAT/CryptInject.PM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 08 00 00 02 00 "
		
	strings :
		$a_81_0 = {24 66 31 33 35 66 31 32 64 2d 34 62 64 36 2d 34 34 66 65 2d 61 34 62 34 2d 33 38 37 63 34 63 33 35 38 62 65 35 } //02 00  $f135f12d-4bd6-44fe-a4b4-387c4c358be5
		$a_81_1 = {43 61 73 68 4d 65 20 4f 75 74 } //02 00  CashMe Out
		$a_81_2 = {43 61 73 68 4d 65 4f 75 74 2e 54 65 78 61 73 2e 72 65 73 6f 75 72 63 65 73 } //02 00  CashMeOut.Texas.resources
		$a_81_3 = {43 61 73 68 4d 65 4f 75 74 2e 42 6c 61 63 6b 4a 61 63 6b 49 6e 73 74 72 75 63 74 69 6f 6e 73 2e 72 65 73 6f 75 72 63 65 73 } //02 00  CashMeOut.BlackJackInstructions.resources
		$a_81_4 = {43 61 73 68 4d 65 4f 75 74 2e 53 6c 6f 74 73 47 61 6d 65 2e 72 65 73 6f 75 72 63 65 73 } //02 00  CashMeOut.SlotsGame.resources
		$a_81_5 = {43 61 73 68 4d 65 4f 75 74 2e 46 69 76 65 43 61 72 64 44 72 61 77 48 6f 6d 65 2e 72 65 73 6f 75 72 63 65 73 } //01 00  CashMeOut.FiveCardDrawHome.resources
		$a_81_6 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  CheckRemoteDebuggerPresent
		$a_81_7 = {54 68 61 6e 6b 73 20 66 6f 72 20 70 6c 61 79 69 6e 67 20 42 6c 61 63 6b 6a 61 63 6b 21 } //00 00  Thanks for playing Blackjack!
	condition:
		any of ($a_*)
 
}