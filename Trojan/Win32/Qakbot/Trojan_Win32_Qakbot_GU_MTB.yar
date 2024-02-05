
rule Trojan_Win32_Qakbot_GU_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.GU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 18 89 1d 90 02 0f 03 05 90 01 04 8b 15 90 01 04 89 02 a1 90 01 04 83 c0 04 a3 90 01 04 33 c0 a3 90 01 04 a1 90 01 04 83 c0 04 03 05 90 01 04 a3 90 01 04 a1 90 01 04 3b 05 90 01 04 0f 82 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}