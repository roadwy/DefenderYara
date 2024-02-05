
rule Trojan_Win32_Vidar_RJ_MTB{
	meta:
		description = "Trojan:Win32/Vidar.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 55 08 03 55 f8 89 55 f0 8b 45 f0 89 45 f4 8b 4d f4 8b 11 33 55 10 8b 45 f4 89 10 } //00 00 
	condition:
		any of ($a_*)
 
}