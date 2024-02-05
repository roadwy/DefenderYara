
rule Trojan_Win32_Vidar_GJE_MTB{
	meta:
		description = "Trojan:Win32/Vidar.GJE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b 45 f8 33 d2 f7 75 fc 52 8b 4d 10 e8 90 01 04 0f be 10 8b 45 08 03 45 f8 0f b6 08 33 ca 8b 55 08 03 55 f8 88 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}