
rule Trojan_BAT_Tnega_YN_MTB{
	meta:
		description = "Trojan:BAT/Tnega.YN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 00 75 00 74 00 6f 00 57 00 69 00 6e 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //01 00  AutoWin.Properties.Resources
		$a_01_1 = {41 00 75 00 74 00 6f 00 55 00 70 00 64 00 61 00 74 00 65 00 72 00 44 00 6f 00 74 00 4e 00 45 00 54 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //01 00  AutoUpdaterDotNET.Properties.Resources
		$a_01_2 = {4d 00 61 00 74 00 65 00 72 00 69 00 61 00 6c 00 53 00 6b 00 69 00 6e 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //01 00  MaterialSkin.Properties.Resources
		$a_01_3 = {4d 00 65 00 74 00 72 00 6f 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //01 00  MetroFramework.Properties.Resources
		$a_81_4 = {47 65 74 53 74 72 69 6e 67 42 61 6c 61 6e 63 65 57 61 6c 6c 65 74 } //01 00  GetStringBalanceWallet
		$a_81_5 = {53 65 6e 64 4d 6f 76 65 42 6f 55 53 44 54 } //01 00  SendMoveBoUSDT
		$a_81_6 = {43 68 65 63 6b 42 69 65 74 44 61 6e 68 } //01 00  CheckBietDanh
		$a_81_7 = {44 6f 77 6e 6c 6f 61 64 43 68 72 6f 6d 65 44 72 69 76 65 72 } //01 00  DownloadChromeDriver
		$a_81_8 = {43 68 75 79 65 6e 74 69 65 6e } //00 00  Chuyentien
	condition:
		any of ($a_*)
 
}