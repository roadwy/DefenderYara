
rule Trojan_Win32_Johnnie_LM_MTB{
	meta:
		description = "Trojan:Win32/Johnnie.LM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8d 9b 00 00 00 00 8a 91 90 01 04 30 90 01 05 83 f9 90 01 01 75 90 01 01 33 c9 eb 90 01 01 41 40 3b c6 72 90 01 01 8b 45 fc ff 90 01 01 6a 00 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Johnnie_LM_MTB_2{
	meta:
		description = "Trojan:Win32/Johnnie.LM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8d a4 24 00 90 02 30 8a 91 90 01 04 30 90 01 05 83 f9 90 01 01 75 90 01 01 33 c9 eb 90 01 01 41 40 3b c6 72 90 01 01 8d 45 90 01 01 50 6a 90 01 01 56 68 90 01 04 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}