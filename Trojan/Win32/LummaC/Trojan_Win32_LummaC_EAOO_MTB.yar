
rule Trojan_Win32_LummaC_EAOO_MTB{
	meta:
		description = "Trojan:Win32/LummaC.EAOO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 fb 89 5c 24 04 8b 5c 24 04 80 c3 78 88 9c 3c e8 53 1f 1e 47 } //5
		$a_01_1 = {21 c7 89 7c 24 04 8b 44 24 04 04 4e 88 84 14 ca e2 4c bf 42 4e } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}