
rule Trojan_Win32_Zbot_XLZ_MTB{
	meta:
		description = "Trojan:Win32/Zbot.XLZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {6b c0 c0 01 85 90 01 04 8a 85 90 01 04 8b 0d 90 01 04 32 85 90 01 04 3b 0d 90 01 04 8b 0d 90 01 04 7f 90 01 01 8b 8d 90 01 04 01 8d 90 01 04 88 06 39 1d 90 01 04 75 90 01 01 8b 85 90 01 04 99 6a 35 59 f7 f9 69 c0 20 2a 01 00 2b c8 01 8d 90 01 04 81 3d 90 01 04 e8 03 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}