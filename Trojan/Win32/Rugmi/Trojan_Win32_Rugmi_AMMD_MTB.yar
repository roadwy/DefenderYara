
rule Trojan_Win32_Rugmi_AMMD_MTB{
	meta:
		description = "Trojan:Win32/Rugmi.AMMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b 4d f8 83 c1 04 89 4d f8 81 7d f8 00 70 00 00 7d 90 01 01 8b 55 e4 03 55 f8 8b 02 03 45 d8 8b 4d f0 03 4d f8 89 01 eb 90 00 } //02 00 
		$a_01_1 = {8d 55 d4 52 8b 45 d4 50 68 00 70 00 00 8b 4d f0 51 ff 55 } //00 00 
	condition:
		any of ($a_*)
 
}