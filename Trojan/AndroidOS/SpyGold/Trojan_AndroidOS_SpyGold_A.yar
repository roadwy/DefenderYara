
rule Trojan_AndroidOS_SpyGold_A{
	meta:
		description = "Trojan:AndroidOS/SpyGold.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 70 6c 6f 61 64 46 69 6c 65 73 2e 61 73 70 78 3f 61 73 6b 49 64 3d 31 26 75 69 64 3d } //01 00 
		$a_01_1 = {61 6c 6c 6f 74 57 6f 72 6b 54 61 73 6b 2e 61 73 70 78 3f 6e 6f 3d } //01 00 
		$a_01_2 = {7a 6a 70 68 6f 6e 65 63 61 6c 6c 2e 74 78 74 } //01 00 
		$a_03_3 = {52 65 67 69 73 74 55 69 64 90 02 01 2e 61 73 70 78 3f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}