
rule Trojan_Win32_Qakbot_NZ_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 c1 2b c8 8b 86 90 01 04 05 90 01 04 81 c1 90 01 04 31 46 90 01 01 b8 90 01 04 2b 46 90 01 01 01 86 90 01 04 8b 86 90 01 04 89 8e 90 01 04 8b 8e 90 01 04 31 04 11 83 c2 90 01 01 8b 86 90 01 04 01 86 90 01 04 81 fa 90 01 04 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}