
rule Trojan_AndroidOS_Smsthief_Y{
	meta:
		description = "Trojan:AndroidOS/Smsthief.Y,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 70 72 6e 63 2e 68 69 64 65 69 63 6f 6e } //2 com.prnc.hideicon
		$a_01_1 = {7a 78 7a 78 7a 78 6e 6f 74 73 65 6e 64 } //1 zxzxzxnotsend
		$a_01_2 = {75 70 69 70 69 6e 64 65 6b 68 } //1 upipindekh
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}