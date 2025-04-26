
rule Trojan_Win32_CoinMiner_CF_bit{
	meta:
		description = "Trojan:Win32/CoinMiner.CF!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {70 6f 6f 6c 2e 73 75 70 70 6f 72 74 78 6d 72 2e 63 6f 6d } //1 pool.supportxmr.com
		$a_01_1 = {70 6f 6f 6c 2e 6d 69 6e 65 78 6d 72 2e 63 6f 6d } //1 pool.minexmr.com
		$a_01_2 = {53 65 74 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 44 69 73 61 62 6c 65 52 65 61 6c 74 69 6d 65 4d 6f 6e 69 74 6f 72 69 6e 67 20 24 74 72 75 65 } //1 Set-MpPreference -DisableRealtimeMonitoring $true
		$a_01_3 = {4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}