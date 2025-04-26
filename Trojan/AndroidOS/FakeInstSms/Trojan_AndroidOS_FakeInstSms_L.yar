
rule Trojan_AndroidOS_FakeInstSms_L{
	meta:
		description = "Trojan:AndroidOS/FakeInstSms.L,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {43 6f 6e 74 65 6e 74 2d 44 69 73 70 6f 73 69 74 69 6f 6e 3a 20 66 6f 72 6d 2d 64 61 74 61 3b 20 6e 61 6d 65 3d 22 6d 61 6e 75 66 61 63 74 75 72 65 72 22 } //1 Content-Disposition: form-data; name="manufacturer"
		$a_00_1 = {4b 53 74 61 72 74 43 6f 6e 74 65 6e 74 } //1 KStartContent
		$a_00_2 = {4c 72 75 2f 61 6c 70 68 61 2f 41 6c 70 68 61 41 70 69 52 65 73 75 6c 74 } //1 Lru/alpha/AlphaApiResult
		$a_00_3 = {4c 72 75 2f 61 6c 70 68 61 2f 41 6c 70 68 61 52 65 63 65 69 76 65 72 } //1 Lru/alpha/AlphaReceiver
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}