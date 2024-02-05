
rule Trojan_Win32_Qakbot_ECG_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.ECG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 46 24 83 e8 90 01 01 01 86 90 01 04 8b 4e 90 01 01 8b 46 90 01 01 31 04 0a 83 c2 90 01 01 8b 46 90 01 01 83 e8 90 01 01 0f af 86 90 01 04 89 86 90 01 04 8b 46 90 01 01 01 46 90 01 01 81 fa 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}