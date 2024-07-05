
rule Trojan_Win32_Vidar_ASGD_MTB{
	meta:
		description = "Trojan:Win32/Vidar.ASGD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {2b d0 8b 45 90 01 01 31 10 83 45 90 01 01 04 6a 00 e8 90 01 03 ff 83 c0 04 01 45 90 01 01 8b 45 90 01 01 3b 45 90 01 01 72 90 00 } //02 00 
		$a_03_1 = {01 02 8b 45 90 01 01 03 45 90 01 01 03 45 90 01 01 89 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}