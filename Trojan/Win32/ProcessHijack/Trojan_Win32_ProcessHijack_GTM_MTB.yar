
rule Trojan_Win32_ProcessHijack_GTM_MTB{
	meta:
		description = "Trojan:Win32/ProcessHijack.GTM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 c1 8b 45 8c c7 44 24 10 40 00 00 00 c7 44 24 0c 00 30 00 00 89 54 24 08 89 4c 24 04 89 04 24 } //5
		$a_01_1 = {8b 45 e4 8b 48 54 8b 45 08 8b 10 8b 45 e4 8b 40 34 89 c3 8b 45 8c c7 44 24 10 00 00 00 00 89 4c 24 0c 89 54 24 08 89 5c 24 04 89 04 24 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}