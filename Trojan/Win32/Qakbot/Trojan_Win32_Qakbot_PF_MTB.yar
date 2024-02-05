
rule Trojan_Win32_Qakbot_PF_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.PF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {2d a2 d1 00 00 03 05 90 02 04 a3 90 01 04 a1 90 01 04 a3 90 01 04 6a 01 90 02 d0 6a 01 e8 90 01 04 a1 90 01 04 03 05 90 01 04 8b 15 90 01 04 31 02 6a 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}