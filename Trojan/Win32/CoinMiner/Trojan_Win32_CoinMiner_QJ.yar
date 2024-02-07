
rule Trojan_Win32_CoinMiner_QJ{
	meta:
		description = "Trojan:Win32/CoinMiner.QJ,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {74 72 79 20 22 22 20 2d 2d 68 65 6c 70 27 20 66 6f 72 20 6d 6f 72 65 20 69 6e 66 6f 72 6d 61 74 69 6f 6e 2e } //02 00  try "" --help' for more information.
		$a_01_1 = {75 73 61 67 65 3a 20 20 5b 6f 70 74 69 6f 6e 73 5d } //01 00  usage:  [options]
		$a_01_2 = {66 65 65 2e 78 6d 72 69 67 2e 63 6f 6d } //01 00  fee.xmrig.com
		$a_01_3 = {2d 6f 2c 20 2d 2d 75 72 6c 3d 55 52 4c } //01 00  -o, --url=URL
		$a_01_4 = {63 72 79 70 74 6f 6e 69 67 68 74 20 28 64 65 66 61 75 6c 74 29 20 6f 72 20 63 72 79 70 74 6f 6e 69 67 68 74 2d 6c 69 74 65 } //01 00  cryptonight (default) or cryptonight-lite
		$a_01_5 = {2d 61 2c 20 2d 2d 61 6c 67 6f 3d 61 6c 67 6f } //00 00  -a, --algo=algo
	condition:
		any of ($a_*)
 
}