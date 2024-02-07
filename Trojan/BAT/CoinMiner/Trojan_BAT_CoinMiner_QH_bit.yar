
rule Trojan_BAT_CoinMiner_QH_bit{
	meta:
		description = "Trojan:BAT/CoinMiner.QH!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {2d 00 6f 00 20 00 78 00 6d 00 72 00 2d 00 90 02 10 2e 00 64 00 77 00 61 00 72 00 66 00 70 00 6f 00 6f 00 6c 00 2e 00 63 00 6f 00 6d 00 3a 00 90 00 } //01 00 
		$a_01_1 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_2 = {5c 58 4d 52 69 67 20 53 74 61 72 74 65 72 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 75 70 64 67 } //01 00  \XMRig Starter\obj\Release\updg
		$a_00_3 = {68 00 6b 00 63 00 6d 00 6b 00 } //00 00  hkcmk
	condition:
		any of ($a_*)
 
}