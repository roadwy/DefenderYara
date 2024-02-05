
rule Trojan_Win32_Qakbot_SAJ_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.SAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {88 06 03 c2 25 90 01 04 88 17 8b 55 90 01 01 8a 44 08 90 01 01 32 04 1a 88 03 43 ff 4d 90 01 01 75 90 00 } //01 00 
		$a_00_1 = {55 70 64 74 } //00 00 
	condition:
		any of ($a_*)
 
}