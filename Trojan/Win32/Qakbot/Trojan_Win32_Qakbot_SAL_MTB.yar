
rule Trojan_Win32_Qakbot_SAL_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.SAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 e3 bb 00 00 00 00 e9 90 01 04 8b 45 90 01 01 0f b6 44 10 90 01 01 33 c8 3a f6 74 90 01 01 8b 45 90 01 01 03 45 90 01 01 0f b6 08 3a c0 74 90 00 } //01 00 
		$a_00_1 = {57 69 6e 64 } //00 00 
	condition:
		any of ($a_*)
 
}