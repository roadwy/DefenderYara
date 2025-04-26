
rule Trojan_Win32_CoinMiner_GG_MTB{
	meta:
		description = "Trojan:Win32/CoinMiner.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,21 00 21 00 08 00 00 "
		
	strings :
		$a_80_0 = {4d 49 4e 45 52 20 7b 30 7d 20 20 20 43 50 55 20 7b 31 7d 25 20 20 20 52 41 4d 20 7b 32 7d 25 } //MINER {0}   CPU {1}%   RAM {2}%  10
		$a_80_1 = {53 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 41 6e 74 69 76 69 72 75 73 50 72 6f 64 75 63 74 } //Select * from AntivirusProduct  10
		$a_80_2 = {2f 63 72 65 61 74 65 20 2f 66 20 2f 73 63 20 4f 4e 4c 4f 47 4f 4e 20 2f 52 4c 20 48 49 47 48 45 53 54 20 2f 74 6e } ///create /f /sc ONLOGON /RL HIGHEST /tn  10
		$a_80_3 = {50 61 73 74 65 62 69 6e } //Pastebin  1
		$a_80_4 = {5c 6e 75 52 5c 6e 6f 69 73 72 65 56 74 6e 65 72 72 75 43 5c 73 77 6f 64 6e 69 57 5c 74 66 6f 73 6f 72 63 69 4d 5c 65 72 61 77 74 66 6f 53 } //\nuR\noisreVtnerruC\swodniW\tfosorciM\erawtfoS  1
		$a_80_5 = {73 63 68 74 61 73 6b 73 2e 65 78 65 } //schtasks.exe  1
		$a_80_6 = {2d 2d 64 6f 6e 61 74 65 2d 6c 65 76 65 6c 3d } //--donate-level=  1
		$a_80_7 = {53 45 4c 45 43 54 20 43 6f 6d 6d 61 6e 64 4c 69 6e 65 20 46 52 4f 4d 20 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 20 57 48 45 52 45 20 50 72 6f 63 65 73 73 49 64 20 3d 20 } //SELECT CommandLine FROM Win32_Process WHERE ProcessId =   1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*10+(#a_80_2  & 1)*10+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1) >=33
 
}