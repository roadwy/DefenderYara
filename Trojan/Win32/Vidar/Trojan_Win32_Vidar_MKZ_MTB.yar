
rule Trojan_Win32_Vidar_MKZ_MTB{
	meta:
		description = "Trojan:Win32/Vidar.MKZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {51 52 89 54 24 90 01 01 ff 15 90 01 04 6a 00 6a 00 6a 00 ff 15 90 01 04 6a 00 8d 54 24 90 01 01 52 6a 00 68 90 01 04 6a 00 6a 00 ff 15 90 01 04 31 7c 24 90 01 01 8b 44 24 90 01 01 31 44 24 90 01 01 8b 44 24 90 01 01 29 44 24 90 01 01 8b 15 90 01 04 81 fa 90 01 04 74 90 01 01 81 c3 90 01 04 ff 4c 24 90 01 01 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}