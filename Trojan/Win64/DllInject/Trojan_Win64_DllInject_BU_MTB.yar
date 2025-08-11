
rule Trojan_Win64_DllInject_BU_MTB{
	meta:
		description = "Trojan:Win64/DllInject.BU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {31 37 31 36 37 37 38 37 37 30 73 74 65 61 6c 65 72 2e 64 6c 6c } //1 1716778770stealer.dll
		$a_01_1 = {47 6f 6c 63 6f 6e 64 61 5f 70 6f 70 70 79 63 6f 63 6b 57 69 6c 6c 69 61 6d } //1 Golconda_poppycockWilliam
		$a_01_2 = {62 6c 75 66 66 5f 68 61 6e 64 62 61 6c 6c 73 5f 69 6e 74 65 72 63 65 70 74 6f 72 } //1 bluff_handballs_interceptor
		$a_01_3 = {64 65 63 6c 61 72 61 74 69 6f 6e 5f 62 6c 6f 63 6b 68 6f 75 73 65 5f 72 75 73 74 70 72 6f 6f 66 73 } //1 declaration_blockhouse_rustproofs
		$a_01_4 = {68 61 6e 64 62 61 67 5f 6d 6f 6e 6f 63 6f 74 79 6c 65 64 6f 6e } //1 handbag_monocotyledon
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}