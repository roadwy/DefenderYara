
rule Trojan_AndroidOS_Fakeapp_L{
	meta:
		description = "Trojan:AndroidOS/Fakeapp.L,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {64 69 61 6e 70 69 6e 67 3a 2f 2f } //1 dianping://
		$a_01_1 = {68 74 74 70 3a 2f 2f 77 61 70 2e 63 6e 61 6e 7a 68 69 2e 63 6f 6d } //1 http://wap.cnanzhi.com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}