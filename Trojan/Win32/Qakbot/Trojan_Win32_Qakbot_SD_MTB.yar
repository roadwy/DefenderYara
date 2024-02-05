
rule Trojan_Win32_Qakbot_SD_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.SD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 48 3c 81 f7 90 01 04 0f af fb 8d 41 90 01 01 f7 d0 03 fa 8b 52 90 01 01 4a 03 d1 85 d0 90 00 } //01 00 
		$a_03_1 = {33 cb 42 89 4e 90 01 01 69 85 90 01 08 3b d0 76 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}