
rule Trojan_Win32_Vidar_PAI_MTB{
	meta:
		description = "Trojan:Win32/Vidar.PAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b c8 33 d2 8b c3 f7 f1 8b 85 90 01 04 8b 8d 90 01 04 8a 04 02 32 04 31 88 06 8d 85 90 01 04 50 8d 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}