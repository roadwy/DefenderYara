
rule Misleading_MacOS_CoinMiner_BC_MTB{
	meta:
		description = "Misleading:MacOS/CoinMiner.BC!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {6d 69 6e 69 6e 67 2e 73 65 74 5f 74 61 72 67 65 74 } //1 mining.set_target
		$a_00_1 = {73 74 72 61 74 75 6d 2b 73 73 6c 3a 2f 2f 72 61 6e 64 6f 6d 78 2e 78 6d 72 69 67 2e 63 6f 6d 3a 34 34 33 } //1 stratum+ssl://randomx.xmrig.com:443
		$a_00_2 = {64 6f 6e 61 74 65 2e 76 32 2e 78 6d 72 69 67 2e 63 6f 6d 3a 33 33 33 33 } //1 donate.v2.xmrig.com:3333
		$a_00_3 = {2e 63 6f 6e 66 69 67 2f 78 6d 72 69 67 2e 6a 73 6f 6e } //1 .config/xmrig.json
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}