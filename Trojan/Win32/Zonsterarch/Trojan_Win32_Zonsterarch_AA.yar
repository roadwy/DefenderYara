
rule Trojan_Win32_Zonsterarch_AA{
	meta:
		description = "Trojan:Win32/Zonsterarch.AA,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {61 6c 74 5f 70 61 79 5f 62 61 73 65 5f 75 72 6c } //1 alt_pay_base_url
		$a_01_1 = {61 00 72 00 63 00 68 00 69 00 76 00 65 00 2e 00 73 00 6d 00 73 00 63 00 6f 00 75 00 6e 00 74 00 } //1 archive.smscount
		$a_01_2 = {22 00 7a 00 6d 00 5f 00 63 00 6f 00 75 00 6e 00 74 00 72 00 79 00 22 00 } //1 "zm_country"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}