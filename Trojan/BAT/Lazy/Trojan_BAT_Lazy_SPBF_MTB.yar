
rule Trojan_BAT_Lazy_SPBF_MTB{
	meta:
		description = "Trojan:BAT/Lazy.SPBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {17 58 07 8e 69 5d 13 10 07 11 10 91 13 11 11 0f 11 11 59 20 00 01 00 00 58 20 ff 00 00 00 5f 13 12 } //2
		$a_01_1 = {07 11 0d 91 11 0e 61 13 0f 11 26 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}