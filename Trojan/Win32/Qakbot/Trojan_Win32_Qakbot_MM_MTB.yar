
rule Trojan_Win32_Qakbot_MM_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.MM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 82 80 00 00 00 31 42 40 b8 90 01 04 2b 82 90 01 04 01 82 90 01 04 8b 42 48 2d 90 01 04 01 42 68 8b 82 90 01 04 01 42 74 b8 90 01 04 2b 42 30 01 82 90 01 04 8b 82 d0 00 00 00 33 42 68 35 90 01 04 89 42 68 81 fe 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}