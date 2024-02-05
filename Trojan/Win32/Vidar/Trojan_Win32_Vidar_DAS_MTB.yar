
rule Trojan_Win32_Vidar_DAS_MTB{
	meta:
		description = "Trojan:Win32/Vidar.DAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {01 02 8b 45 c4 03 45 94 03 45 ec 03 45 9c 89 45 a4 6a 00 e8 90 02 04 8b 55 a4 2b d0 8b 45 d4 31 10 83 45 ec 04 83 45 d4 04 8b 45 ec 3b 45 d0 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}