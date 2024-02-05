
rule Trojan_Win32_Qakbot_SAB_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.SAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {40 0f af 46 90 01 01 89 46 90 01 01 8b 46 90 01 01 2d 90 01 04 31 46 90 01 01 8b 46 90 01 01 35 90 01 04 29 46 90 01 01 8b 86 90 01 04 09 86 90 01 04 8b 86 90 01 04 01 86 90 01 04 81 fb 90 01 04 0f 8c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}