
rule Trojan_Win32_Qakbot_SAF_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.SAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b d8 8b 46 90 01 01 89 9e 90 01 04 31 04 29 83 c5 90 01 01 8b 46 90 01 01 48 01 46 90 01 01 8b 46 90 01 01 01 46 90 01 01 81 fd 90 01 04 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}