
rule Trojan_Win32_Qakbot_KMG_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {83 e9 15 89 0d 90 01 04 8b 15 90 01 04 03 55 90 01 01 03 15 90 01 04 89 15 90 01 04 a1 90 01 04 2b 05 90 01 04 a3 90 01 04 b9 01 00 00 00 85 c9 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}