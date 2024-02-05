
rule Trojan_Win32_Qakbot_SB_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.SB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 86 4c 01 00 00 31 46 90 01 01 48 89 86 90 01 04 8b 86 90 01 04 2d 90 01 04 89 46 90 01 01 ff 77 90 01 01 8b 46 90 01 01 03 47 90 01 01 50 8b 47 90 01 01 03 46 90 01 01 50 e8 90 00 } //01 00 
		$a_00_1 = {44 51 46 69 46 61 30 79 } //00 00 
	condition:
		any of ($a_*)
 
}