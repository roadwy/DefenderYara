
rule Trojan_Win32_CoinMiner_OF_bit{
	meta:
		description = "Trojan:Win32/CoinMiner.OF!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 74 72 20 22 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 75 72 6c 2e 64 6c 6c 2c 4f 70 65 6e 55 52 4c 41 } //1 /tr "rundll32.exe url.dll,OpenURLA
		$a_01_1 = {73 68 75 74 64 6f 77 6e 20 2d 73 20 2d 74 20 31 } //1 shutdown -s -t 1
		$a_03_2 = {50 72 6f 63 65 73 73 20 48 61 63 6b 65 72 90 02 03 41 6e 56 69 72 90 00 } //1
		$a_01_3 = {4c 53 31 6b 62 32 35 68 64 47 55 74 62 47 56 32 5a 57 77 39 4d 51 3d 3d } //2 LS1kb25hdGUtbGV2ZWw9MQ==
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*2) >=3
 
}
rule Trojan_Win32_CoinMiner_OF_bit_2{
	meta:
		description = "Trojan:Win32/CoinMiner.OF!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 74 6e 20 5c 53 79 73 74 61 73 6b 73 5c 53 65 72 76 69 63 65 52 75 6e 20 2f 74 72 20 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c } //1 schtasks /create /tn \Systasks\ServiceRun /tr "C:\ProgramData\
		$a_01_1 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 61 74 74 72 69 62 2e 65 78 65 } //1 taskkill /f /im attrib.exe
		$a_01_2 = {61 74 74 72 69 62 20 2b 73 20 2b 68 20 25 75 73 65 72 70 72 6f 66 69 6c 65 25 5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 } //1 attrib +s +h %userprofile%\AppData\Roaming
		$a_01_3 = {54 61 73 6b 6d 67 72 2e 65 78 65 00 74 61 73 6b 6d 67 72 2e 65 78 65 00 50 72 6f 63 65 73 73 48 61 63 6b 65 72 2e 65 78 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}
rule Trojan_Win32_CoinMiner_OF_bit_3{
	meta:
		description = "Trojan:Win32/CoinMiner.OF!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {69 70 6c 6f 67 67 65 72 2e 63 6f 6d } //2 iplogger.com
		$a_01_1 = {78 6d 72 2e 70 6f 6f 6c 2e 6d 69 6e 65 72 67 61 74 65 2e 63 6f 6d } //1 xmr.pool.minergate.com
		$a_03_2 = {5c 57 69 6e 64 6f 77 73 54 61 73 6b 5c 90 02 10 2e 65 78 65 20 2f 72 69 20 31 20 2f 73 74 20 30 30 3a 30 30 20 2f 64 75 20 39 39 39 39 3a 35 39 20 2f 73 63 20 64 61 69 6c 79 20 2f 66 90 00 } //2
		$a_01_3 = {70 00 72 00 6f 00 63 00 65 00 78 00 70 00 2e 00 65 00 78 00 65 00 00 00 74 00 61 00 73 00 6b 00 6d 00 67 00 72 00 2e 00 65 00 78 00 65 00 } //1
		$a_01_4 = {54 00 61 00 73 00 6b 00 6d 00 67 00 72 00 2e 00 65 00 78 00 65 00 00 00 41 00 6e 00 56 00 69 00 72 00 2e 00 65 00 78 00 65 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_03_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}