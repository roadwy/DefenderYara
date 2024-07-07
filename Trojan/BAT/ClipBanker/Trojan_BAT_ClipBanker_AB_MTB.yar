
rule Trojan_BAT_ClipBanker_AB_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 05 00 00 "
		
	strings :
		$a_00_0 = {40 01 57 d4 02 fc c9 02 } //5
		$a_00_1 = {fa 25 33 00 16 00 00 02 00 00 00 2c 00 00 00 0b 00 00 00 2b } //10
		$a_00_2 = {76 34 2e 30 2e 33 30 33 31 39 00 00 00 00 00 00 00 00 09 } //5
		$a_80_3 = {41 73 73 65 6d 62 6c 79 54 72 61 64 65 6d 61 72 6b 41 74 74 72 69 62 75 74 65 } //AssemblyTrademarkAttribute  3
		$a_80_4 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //get_CurrentDomain  3
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*10+(#a_00_2  & 1)*5+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3) >=21
 
}
rule Trojan_BAT_ClipBanker_AB_MTB_2{
	meta:
		description = "Trojan:BAT/ClipBanker.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 05 00 00 "
		
	strings :
		$a_00_0 = {40 01 57 d4 02 fc c9 02 } //5
		$a_00_1 = {fa 25 33 00 16 00 00 02 00 00 00 2d 00 00 00 0b 00 00 00 2b 00 00 00 39 00 00 00 3b 00 00 00 0f 00 00 00 01 00 00 00 01 00 00 00 11 } //10
		$a_00_2 = {76 34 2e 30 2e 33 30 33 31 39 00 00 00 00 00 00 00 00 09 } //5
		$a_80_3 = {41 73 73 65 6d 62 6c 79 54 72 61 64 65 6d 61 72 6b 41 74 74 72 69 62 75 74 65 } //AssemblyTrademarkAttribute  3
		$a_80_4 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //get_CurrentDomain  3
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*10+(#a_00_2  & 1)*5+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3) >=21
 
}