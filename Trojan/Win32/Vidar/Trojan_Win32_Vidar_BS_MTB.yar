
rule Trojan_Win32_Vidar_BS_MTB{
	meta:
		description = "Trojan:Win32/Vidar.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c8 8b 45 90 01 01 33 d2 f7 f1 8b 45 90 01 01 8b 4d 90 01 01 c7 04 24 90 01 04 8a 04 02 32 04 19 88 03 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}