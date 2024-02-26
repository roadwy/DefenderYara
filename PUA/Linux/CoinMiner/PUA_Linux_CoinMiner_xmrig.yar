
rule PUA_Linux_CoinMiner_xmrig{
	meta:
		description = "PUA:Linux/CoinMiner!xmrig,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {67 69 74 68 75 62 2e 63 6f 6d 2f 78 6d 72 69 67 2f 78 6d 72 69 67 2f 72 65 6c 65 61 73 65 73 2f 64 6f 77 6e 6c 6f 61 64 } //00 00  github.com/xmrig/xmrig/releases/download
	condition:
		any of ($a_*)
 
}