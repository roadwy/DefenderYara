
rule Trojan_AndroidOS_FakeInst_X_MTB{
	meta:
		description = "Trojan:AndroidOS/FakeInst.X!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {74 6f 70 66 69 6c 65 73 73 2e 63 6f 6d 2f 72 61 74 65 73 2e 70 68 70 } //1 topfiless.com/rates.php
		$a_01_1 = {63 6f 6d 2f 73 65 6e 64 2f 6c 6f 61 64 65 72 } //1 com/send/loader
		$a_01_2 = {61 67 72 65 65 6d 65 6e 74 2e 74 78 74 } //1 agreement.txt
		$a_01_3 = {67 65 74 4e 65 74 77 6f 72 6b 43 6f 75 6e 74 72 79 49 73 6f } //1 getNetworkCountryIso
		$a_01_4 = {72 75 5f 6d 65 67 61 } //1 ru_mega
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}