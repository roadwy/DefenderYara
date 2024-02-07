
rule Trojan_BAT_CoinMiner_QG_bit{
	meta:
		description = "Trojan:BAT/CoinMiner.QG!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {6f 62 6a 5c 44 65 62 75 67 5c 57 69 6e 43 61 6c 65 6e 64 61 72 2e 70 64 62 } //01 00  obj\Debug\WinCalendar.pdb
		$a_01_1 = {73 67 76 68 6f 73 74 73 20 2d 63 20 73 67 6d 69 6e 65 72 7a 63 61 73 68 2e 63 6f 6e 66 20 2d 2d 67 70 75 2d 72 65 6f 72 64 65 72 } //00 00  sgvhosts -c sgminerzcash.conf --gpu-reorder
	condition:
		any of ($a_*)
 
}