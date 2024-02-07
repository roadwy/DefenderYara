
rule Trojan_Win32_Zusy_HNS_MTB{
	meta:
		description = "Trojan:Win32/Zusy.HNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 6e 74 65 72 6e 65 74 47 65 74 43 6f 6e 6e 65 63 74 65 64 53 74 61 74 65 } //01 00  InternetGetConnectedState
		$a_01_1 = {20 20 20 20 20 20 20 20 20 2e 65 78 65 00 00 00 ff ff ff ff 04 00 00 00 2e 65 78 65 } //01 00 
		$a_01_2 = {20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 2e 65 78 65 00 55 } //00 00 
	condition:
		any of ($a_*)
 
}