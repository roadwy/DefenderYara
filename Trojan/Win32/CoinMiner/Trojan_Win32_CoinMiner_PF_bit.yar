
rule Trojan_Win32_CoinMiner_PF_bit{
	meta:
		description = "Trojan:Win32/CoinMiner.PF!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 65 78 65 20 2d 6f 20 70 6f 6f 6c 2e 6d 69 6e 65 78 6d 72 2e 63 6f 6d } //01 00  .exe -o pool.minexmr.com
		$a_01_1 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 28 29 b5 f7 d3 c3 ca a7 b0 dc 21 } //00 00 
	condition:
		any of ($a_*)
 
}