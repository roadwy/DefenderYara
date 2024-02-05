
rule Trojan_Win32_Qakbot_FK_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.FK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 d8 8b 45 d8 33 18 89 5d a0 e8 90 01 04 8b 5d a0 2b d8 e8 90 01 04 03 d8 8b 45 d8 89 18 8b 45 d8 83 c0 04 89 45 d8 33 c0 89 45 a4 8b 45 a8 83 c0 04 03 45 a4 89 45 a8 8b 45 a8 3b 45 cc 0f 82 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}