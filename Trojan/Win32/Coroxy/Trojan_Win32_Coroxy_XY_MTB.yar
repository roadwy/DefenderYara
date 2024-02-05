
rule Trojan_Win32_Coroxy_XY_MTB{
	meta:
		description = "Trojan:Win32/Coroxy.XY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {02 c2 eb 00 36 8a 8c 28 00 fc ff ff eb 40 } //01 00 
		$a_01_1 = {36 88 8c 2b 00 fc ff ff e9 54 ff ff ff } //01 00 
		$a_01_2 = {36 88 94 28 00 fc ff ff e9 73 ff ff ff } //01 00 
		$a_01_3 = {02 ca e9 e5 00 00 00 } //01 00 
		$a_01_4 = {36 8a 8c 29 00 fc ff ff eb bb } //01 00 
		$a_01_5 = {30 0e eb 34 } //00 00 
	condition:
		any of ($a_*)
 
}