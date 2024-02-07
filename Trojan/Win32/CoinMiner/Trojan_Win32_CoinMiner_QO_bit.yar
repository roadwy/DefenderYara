
rule Trojan_Win32_CoinMiner_QO_bit{
	meta:
		description = "Trojan:Win32/CoinMiner.QO!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 31 35 2c 31 31 36 2c 31 31 34 2c 39 37 2c 31 31 36 2c 31 31 37 2c 31 30 39 2c 34 33 2c 31 31 36 2c 39 39 2c 31 31 32 2c 35 38 } //01 00  115,116,114,97,116,117,109,43,116,99,112,58
		$a_01_1 = {5c 46 6f 6e 74 73 5c 31 73 61 73 73 2e 65 78 65 } //01 00  \Fonts\1sass.exe
		$a_01_2 = {5c 4d 53 42 75 69 6c 64 5c 53 65 72 76 69 63 65 73 2e 65 78 65 } //00 00  \MSBuild\Services.exe
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_CoinMiner_QO_bit_2{
	meta:
		description = "Trojan:Win32/CoinMiner.QO!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 74 72 61 74 75 6d 2b 74 63 70 3a 2f 2f 78 6d 72 2e 70 6f 6f 6c 2e 6d 69 6e 65 72 67 61 74 65 2e 63 6f 6d 3a } //01 00  stratum+tcp://xmr.pool.minergate.com:
		$a_01_1 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c } //01 00  \Microsoft\Windows\Start Menu\Programs\Startup\
		$a_01_2 = {55 73 61 67 65 3a 20 78 6d 72 69 67 20 5b 4f 50 54 49 4f 4e 53 5d } //00 00  Usage: xmrig [OPTIONS]
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_CoinMiner_QO_bit_3{
	meta:
		description = "Trojan:Win32/CoinMiner.QO!bit,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 05 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 70 6d 78 6d 72 6e 75 6c 6c 2e 64 79 6e 75 2e 6e 65 74 3a } //02 00  http://pmxmrnull.dynu.net:
		$a_01_1 = {50 61 6e 64 65 6d 69 63 2d 43 6f 6e 74 72 6f 6c 6c 65 72 2d 58 4d 52 49 67 } //01 00  Pandemic-Controller-XMRIg
		$a_01_2 = {2f 74 61 73 6b 73 2f 67 65 74 54 61 73 6b } //01 00  /tasks/getTask
		$a_01_3 = {52 45 47 20 41 44 44 20 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 20 2f 76 } //01 00  REG ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v
		$a_01_4 = {73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 73 63 20 6d 69 6e 75 74 65 20 20 2f 6d 6f 20 31 20 2f 74 6e } //01 00  schtasks /create /sc minute  /mo 1 /tn
		$a_01_5 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d } //00 00  taskkill /f /im
	condition:
		any of ($a_*)
 
}