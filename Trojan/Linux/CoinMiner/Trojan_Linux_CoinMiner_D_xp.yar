
rule Trojan_Linux_CoinMiner_D_xp{
	meta:
		description = "Trojan:Linux/CoinMiner.D!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 70 79 2d 63 6c 69 65 6e 74 2e 63 70 70 } //01 00  spy-client.cpp
		$a_01_1 = {74 6f 75 63 68 20 2d 72 20 2f 62 69 6e 2f 73 68 20 25 73 } //01 00  touch -r /bin/sh %s
		$a_01_2 = {63 68 6d 6f 64 20 2b 78 20 25 73 20 31 3e 2f 64 65 76 2f 6e 75 6c 6c 20 32 3e } //01 00  chmod +x %s 1>/dev/null 2>
		$a_01_3 = {63 70 20 2d 66 20 25 73 20 25 73 20 31 3e 2f 64 65 76 2f 6e 75 6c 6c 20 32 3e } //01 00  cp -f %s %s 1>/dev/null 2>
		$a_01_4 = {5b 6b 64 6d 66 6c 75 73 68 5d } //00 00  [kdmflush]
	condition:
		any of ($a_*)
 
}