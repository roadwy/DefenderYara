
rule Trojan_Win32_CoinMiner_QT_bit{
	meta:
		description = "Trojan:Win32/CoinMiner.QT!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 70 69 2e 66 6f 78 6f 76 73 6b 79 2e 72 75 } //01 00  api.foxovsky.ru
		$a_01_1 = {5b 43 50 55 4d 69 6e 65 72 54 68 72 65 61 64 5d 20 2d 20 53 55 43 43 45 53 53 20 69 6e 6a 65 63 74 65 64 20 74 6f 20 70 49 64 3a } //01 00  [CPUMinerThread] - SUCCESS injected to pId:
		$a_01_2 = {5b 57 69 6e 4d 61 69 6e 5d 20 2d 20 42 6f 74 20 69 6e 73 74 61 6c 6c 65 64 2c 20 73 74 61 72 74 20 53 75 70 72 65 6d 65 54 68 72 65 61 64 } //01 00  [WinMain] - Bot installed, start SupremeThread
		$a_01_3 = {2f 67 61 74 65 2f 63 6f 6e 6e 65 63 74 69 6f 6e 2e 70 68 70 } //01 00  /gate/connection.php
		$a_01_4 = {69 6e 73 74 61 6c 6c 00 64 64 6f 73 } //00 00  湩瑳污l摤獯
	condition:
		any of ($a_*)
 
}