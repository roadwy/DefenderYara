
rule Trojan_Win32_Qakbot_SAI_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.SAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 04 3e 8b 4d 90 01 01 02 c2 0f b6 c0 8a 04 38 30 04 90 01 01 43 8a 45 0b 3b 5d 90 01 01 7c 90 00 } //01 00 
		$a_00_1 = {55 70 64 74 } //00 00 
	condition:
		any of ($a_*)
 
}