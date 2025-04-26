
rule Trojan_BAT_CoinMiner_CA_bit{
	meta:
		description = "Trojan:BAT/CoinMiner.CA!bit,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 07 00 00 "
		
	strings :
		$a_01_0 = {44 65 74 65 63 74 6f 72 49 73 53 74 61 72 74 } //1 DetectorIsStart
		$a_01_1 = {45 6e 65 6d 79 4b 69 6c 6c 65 72 } //1 EnemyKiller
		$a_01_2 = {4d 69 6e 65 72 57 72 69 74 74 65 72 } //1 MinerWritter
		$a_01_3 = {47 6f 46 75 63 6b 55 61 63 } //1 GoFuckUac
		$a_01_4 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 43 00 6c 00 61 00 73 00 73 00 65 00 73 00 5c 00 6d 00 73 00 63 00 66 00 69 00 6c 00 65 00 5c 00 73 00 68 00 65 00 6c 00 6c 00 5c 00 6f 00 70 00 65 00 6e 00 5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 } //1 Software\Classes\mscfile\shell\open\command
		$a_01_5 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 5c 00 } //1 Software\Microsoft\Windows\CurrentVersion\Run\
		$a_01_6 = {2d 00 6f 00 20 00 73 00 74 00 72 00 61 00 74 00 75 00 6d 00 2b 00 74 00 63 00 70 00 3a 00 2f 00 2f 00 } //10 -o stratum+tcp://
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*10) >=14
 
}