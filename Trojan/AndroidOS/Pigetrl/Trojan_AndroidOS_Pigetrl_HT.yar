
rule Trojan_AndroidOS_Pigetrl_HT{
	meta:
		description = "Trojan:AndroidOS/Pigetrl.HT,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 6c 6f 6c 6f 6c 6f 2e 4d 61 69 6e 41 63 74 69 76 69 74 79 } //1 com.lololo.MainActivity
		$a_01_1 = {4c 6f 63 6b 53 65 72 76 69 63 65 24 31 30 30 30 30 30 30 30 30 } //1 LockService$100000000
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}