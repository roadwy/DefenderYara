
rule Trojan_AndroidOS_Basbanke_G_MTB{
	meta:
		description = "Trojan:AndroidOS/Basbanke.G!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 6d 73 73 79 6e 63 73 65 72 76 69 63 65 } //01 00  smssyncservice
		$a_01_1 = {72 75 6e 44 69 72 65 63 74 6c 79 } //01 00  runDirectly
		$a_01_2 = {6d 73 67 62 6f 78 5f 72 65 73 75 6c 74 } //01 00  msgbox_result
		$a_01_3 = {63 6f 6d 2e 6b 31 73 6f 6c 75 74 69 6f 6e 73 2e 64 65 70 6f 73 69 74 2e 73 79 73 74 65 6d } //01 00  com.k1solutions.deposit.system
		$a_01_4 = {5f 62 61 6e 6b 5f 6e 75 6d 62 65 72 5f 6b 62 61 6e 6b } //00 00  _bank_number_kbank
	condition:
		any of ($a_*)
 
}