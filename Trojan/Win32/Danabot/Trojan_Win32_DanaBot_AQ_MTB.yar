
rule Trojan_Win32_DanaBot_AQ_MTB{
	meta:
		description = "Trojan:Win32/DanaBot.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {66 0f 57 c0 66 0f 13 05 90 02 30 8b 85 90 01 04 03 85 90 01 04 89 85 90 01 04 8b 85 90 01 04 33 85 90 01 04 89 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}