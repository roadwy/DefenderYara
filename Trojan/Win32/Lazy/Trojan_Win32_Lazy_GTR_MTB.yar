
rule Trojan_Win32_Lazy_GTR_MTB{
	meta:
		description = "Trojan:Win32/Lazy.GTR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 01 0b 01 0e 2a 00 d2 00 00 00 1a 00 } //5
		$a_01_1 = {40 00 00 40 2e 41 43 45 30 00 00 00 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}