
rule Trojan_AndroidOS_Booger_A{
	meta:
		description = "Trojan:AndroidOS/Booger.A,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {5b 61 6e 7a 68 75 6f 5f 74 65 73 74 5d } //1 [anzhuo_test]
		$a_00_1 = {4c 63 6e 2f 63 6f 6d 2f 78 69 61 6f 6c 2f 6c 69 76 65 77 61 6c 6c 70 61 70 65 72 2f 6a 70 71 63 6d 6e 2f } //1 Lcn/com/xiaol/livewallpaper/jpqcmn/
		$a_00_2 = {63 6f 6d 2e 6d 74 2e 61 69 72 61 64 2e 4d 75 6c 74 69 41 44 } //1 com.mt.airad.MultiAD
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}