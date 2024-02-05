
rule Trojan_Win32_Danabot_AR_MTB{
	meta:
		description = "Trojan:Win32/Danabot.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 f0 03 4d 90 01 01 8d 04 3b 33 c8 0f 57 c0 81 3d 90 02 30 66 0f 13 05 90 01 04 89 4d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}