
rule Trojan_BAT_CoinMiner_R{
	meta:
		description = "Trojan:BAT/CoinMiner.R,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 68 00 75 00 6e 00 74 00 65 00 72 00 63 00 6f 00 64 00 65 00 2e 00 72 00 75 00 2f 00 75 00 70 00 64 00 61 00 74 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 http://huntercode.ru/updater.exe
		$a_01_1 = {5c 4d 69 6e 65 72 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 4f 74 6d 69 76 61 74 65 6c 6e 69 74 65 73 2e 70 64 62 } //1 \Miner\obj\Release\Otmivatelnites.pdb
		$a_01_2 = {5c 4d 69 63 72 6f 73 6f 66 74 65 72 5c 73 76 63 68 6f 73 74 2e 65 78 65 } //1 \Microsofter\svchost.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}