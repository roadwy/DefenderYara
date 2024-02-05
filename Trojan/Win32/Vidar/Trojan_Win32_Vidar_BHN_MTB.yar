
rule Trojan_Win32_Vidar_BHN_MTB{
	meta:
		description = "Trojan:Win32/Vidar.BHN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {d3 e8 89 44 24 14 8b 44 24 34 01 44 24 14 8b 44 24 24 31 44 24 10 8b 4c 24 10 8b 54 24 14 51 52 8d 44 24 90 01 01 50 e8 90 01 04 8b 4c 24 10 8d 44 24 2c 90 01 04 ff 8d 44 24 28 e8 90 01 04 83 6c 24 90 01 02 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}