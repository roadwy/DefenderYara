
rule Trojan_Win32_LummaC_GTG_MTB{
	meta:
		description = "Trojan:Win32/LummaC.GTG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {20 20 20 00 20 20 20 20 00 00 05 00 00 10 00 00 00 60 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 ac 01 } //5
		$a_01_1 = {4a 00 00 04 00 00 00 98 1c 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 74 61 67 67 61 6e 74 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}