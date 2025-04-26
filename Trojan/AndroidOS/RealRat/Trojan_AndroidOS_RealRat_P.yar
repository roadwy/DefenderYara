
rule Trojan_AndroidOS_RealRat_P{
	meta:
		description = "Trojan:AndroidOS/RealRat.P,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {26 61 63 74 69 6f 6e 3d 6f 66 66 6c 69 6e 65 4f 66 66 26 73 63 72 65 65 6e 3d } //2 &action=offlineOff&screen=
		$a_01_1 = {5f 62 61 6e 6b 5f 66 69 6e 64 62 61 6c 61 6e 63 65 } //2 _bank_findbalance
		$a_01_2 = {5f 63 68 65 63 6b 73 63 72 65 65 6e 73 74 61 74 75 73 } //2 _checkscreenstatus
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=4
 
}