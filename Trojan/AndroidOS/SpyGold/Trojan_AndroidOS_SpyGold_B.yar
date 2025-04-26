
rule Trojan_AndroidOS_SpyGold_B{
	meta:
		description = "Trojan:AndroidOS/SpyGold.B,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2f 47 6f 6c 64 44 72 65 61 6d 2f 54 69 6e 67 54 69 6e 67 } //1 /GoldDream/TingTing
		$a_01_1 = {6c 65 62 61 72 2e 67 69 63 70 2e 6e 65 74 2f 75 70 64 61 74 65 5f 73 6f 66 74 2e } //1 lebar.gicp.net/update_soft.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}