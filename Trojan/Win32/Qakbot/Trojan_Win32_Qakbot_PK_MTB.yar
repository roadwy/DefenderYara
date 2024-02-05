
rule Trojan_Win32_Qakbot_PK_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.PK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 d8 8b 45 90 01 01 33 18 89 5d 90 01 01 8b 45 90 01 01 8b 55 90 01 01 89 02 33 c0 89 45 90 01 01 8b 45 90 01 01 83 c0 04 03 45 90 01 01 89 45 90 01 01 8b 45 90 01 01 83 c0 04 03 45 90 01 01 89 45 90 01 01 8b 45 90 01 01 3b 45 90 01 01 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}