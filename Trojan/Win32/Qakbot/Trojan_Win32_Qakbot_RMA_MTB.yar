
rule Trojan_Win32_Qakbot_RMA_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {05 70 83 07 01 a3 90 01 04 8b 0d 90 01 04 03 4d 90 01 01 8b 15 90 01 04 89 91 90 01 04 a1 90 01 04 6b c0 03 03 05 90 01 04 66 89 45 90 01 01 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}