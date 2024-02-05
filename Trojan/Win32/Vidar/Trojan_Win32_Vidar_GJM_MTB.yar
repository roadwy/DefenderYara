
rule Trojan_Win32_Vidar_GJM_MTB{
	meta:
		description = "Trojan:Win32/Vidar.GJM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8a 10 8b 85 90 01 04 32 d1 88 14 18 8b 8d 90 01 04 ff 85 90 01 04 51 43 e8 90 01 04 83 c4 90 01 01 39 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}