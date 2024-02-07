
rule Trojan_Win32_CoinMiner_DE_bit{
	meta:
		description = "Trojan:Win32/CoinMiner.DE!bit,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {64 65 6c 78 6d 72 2e 62 61 74 } //02 00  delxmr.bat
		$a_01_1 = {73 76 63 68 6f 73 74 2e 65 78 65 } //02 00  svchost.exe
		$a_01_2 = {73 74 72 61 74 75 6d 2b 74 63 70 3a 2f 2f 70 6f 6f 6c 2e 6d 69 6e 65 78 6d 72 2e 63 6f 6d 3a 37 37 37 37 20 2d 75 } //01 00  stratum+tcp://pool.minexmr.com:7777 -u
		$a_01_3 = {6d 69 6e 65 72 67 61 74 65 2e 63 6f 6d } //01 00  minergate.com
		$a_01_4 = {6e 69 63 65 68 61 73 68 2e 63 6f 6d } //00 00  nicehash.com
	condition:
		any of ($a_*)
 
}