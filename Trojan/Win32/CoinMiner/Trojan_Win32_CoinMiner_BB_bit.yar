
rule Trojan_Win32_CoinMiner_BB_bit{
	meta:
		description = "Trojan:Win32/CoinMiner.BB!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {44 00 69 00 73 00 70 00 6c 00 61 00 79 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //1
		$a_00_1 = {2f 63 20 22 74 69 6d 65 6f 75 74 20 2f 54 20 34 20 2f 4e 4f 42 52 45 41 4b 20 26 20 6d 6f 76 65 20 2f 59 20 22 25 73 22 20 22 25 73 22 20 26 20 73 74 61 72 74 20 22 22 20 22 25 73 22 22 } //1 /c "timeout /T 4 /NOBREAK & move /Y "%s" "%s" & start "" "%s""
		$a_01_2 = {24 4d 49 4e 45 52 } //1 $MINER
		$a_01_3 = {32 66 36 62 33 38 33 38 30 64 36 65 66 33 35 63 64 39 34 62 64 64 31 62 } //1 2f6b38380d6ef35cd94bdd1b
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Trojan_Win32_CoinMiner_BB_bit_2{
	meta:
		description = "Trojan:Win32/CoinMiner.BB!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 74 72 61 74 75 6d 2b 74 63 70 3a 2f 2f 6d 69 6e 65 2e 6d 6f 6e 65 72 6f 70 6f 6f 6c 2e 63 6f 6d 3a 33 33 33 33 26 } //2 stratum+tcp://mine.moneropool.com:3333&
		$a_01_1 = {73 74 72 61 74 75 6d 2b 74 63 70 3a 2f 2f 6d 6f 6e 65 72 6f 2e 63 72 79 70 74 6f 2d 70 6f 6f 6c 2e 66 72 3a 33 33 33 33 26 } //2 stratum+tcp://monero.crypto-pool.fr:3333&
		$a_01_2 = {73 74 72 61 74 75 6d 2b 74 63 70 3a 2f 2f 78 6d 72 2e 70 72 6f 68 61 73 68 2e 6e 65 74 3a 37 37 37 37 26 } //2 stratum+tcp://xmr.prohash.net:7777&
		$a_01_3 = {73 74 72 61 74 75 6d 2b 74 63 70 3a 2f 2f 70 6f 6f 6c 2e 6d 69 6e 65 78 6d 72 2e 63 6f 6d 3a 35 35 35 35 29 3e 20 25 54 45 4d 50 25 5c } //2 stratum+tcp://pool.minexmr.com:5555)> %TEMP%\
		$a_01_4 = {48 00 4b 00 43 00 55 00 5c 00 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //1 HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1) >=5
 
}