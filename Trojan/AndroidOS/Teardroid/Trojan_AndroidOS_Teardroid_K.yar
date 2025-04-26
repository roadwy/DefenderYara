
rule Trojan_AndroidOS_Teardroid_K{
	meta:
		description = "Trojan:AndroidOS/Teardroid.K,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {72 65 6d 6f 76 65 42 61 74 74 65 72 4f 70 74 } //2 removeBatterOpt
		$a_01_1 = {63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 74 65 61 72 64 72 6f 69 64 76 32 2f 52 65 76 69 76 65 } //2 com/example/teardroidv2/Revive
		$a_01_2 = {67 65 74 56 69 63 74 69 6d 44 61 74 61 73 74 6f 72 65 } //2 getVictimDatastore
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}