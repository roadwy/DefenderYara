
rule Trojan_AndroidOS_SendPay_B_MTB{
	meta:
		description = "Trojan:AndroidOS/SendPay.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 74 61 6c 6b 77 65 62 2f 65 61 73 79 2f 4c 6f 67 69 6e 41 63 74 69 76 69 74 79 } //1 com/talkweb/easy/LoginActivity
		$a_01_1 = {64 65 73 74 69 6e 65 64 5f 78 68 61 6c 66 5f 66 72 65 65 } //1 destined_xhalf_free
		$a_01_2 = {66 72 65 65 5f 61 73 74 72 6f 5f 73 68 61 70 79 } //1 free_astro_shapy
		$a_01_3 = {70 61 79 5f 61 73 74 72 6f 5f 73 68 61 70 79 } //1 pay_astro_shapy
		$a_01_4 = {77 69 61 64 5f 63 61 63 68 65 } //1 wiad_cache
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}