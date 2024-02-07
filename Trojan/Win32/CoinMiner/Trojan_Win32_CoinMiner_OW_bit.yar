
rule Trojan_Win32_CoinMiner_OW_bit{
	meta:
		description = "Trojan:Win32/CoinMiner.OW!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //01 00  Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_1 = {73 00 74 00 72 00 61 00 74 00 75 00 6d 00 2b 00 74 00 63 00 70 00 3a 00 2f 00 2f 00 78 00 6d 00 72 00 2e 00 70 00 6f 00 6f 00 6c 00 2e 00 6d 00 69 00 6e 00 65 00 72 00 67 00 61 00 74 00 65 00 2e 00 63 00 6f 00 6d 00 3a 00 34 00 35 00 35 00 36 00 30 00 } //01 00  stratum+tcp://xmr.pool.minergate.com:45560
		$a_01_2 = {43 00 72 00 65 00 61 00 74 00 65 00 4f 00 62 00 6a 00 65 00 63 00 74 00 28 00 22 00 57 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 53 00 68 00 65 00 6c 00 6c 00 22 00 29 00 2e 00 52 00 75 00 6e 00 } //01 00  CreateObject("Wscript.Shell").Run
		$a_01_3 = {4b 69 6c 6c } //01 00  Kill
		$a_01_4 = {61 64 64 5f 53 68 75 74 64 6f 77 6e } //00 00  add_Shutdown
	condition:
		any of ($a_*)
 
}