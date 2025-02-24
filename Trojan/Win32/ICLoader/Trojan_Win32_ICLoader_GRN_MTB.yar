
rule Trojan_Win32_ICLoader_GRN_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.GRN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {40 00 00 c0 2e 72 73 72 63 00 00 00 00 7a 06 00 00 40 24 } //5
		$a_01_1 = {40 00 00 40 2e 64 61 74 61 00 00 00 b8 53 00 00 00 e0 23 00 00 30 00 00 00 c8 23 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}