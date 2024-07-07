
rule Trojan_BAT_AsyncRAT_AM_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 0e 11 0a 02 11 0a 91 03 11 0a 03 } //2
		$a_01_1 = {06 61 d2 9c } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}