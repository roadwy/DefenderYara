
rule Trojan_Win32_Vidar_AMS_MTB{
	meta:
		description = "Trojan:Win32/Vidar.AMS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 55 a4 2b d0 8b 45 d4 31 10 83 45 ec 04 83 45 d4 04 8b 45 ec 3b 45 d0 72 } //00 00 
	condition:
		any of ($a_*)
 
}