
rule Trojan_Win32_Vidar_PAN_MTB{
	meta:
		description = "Trojan:Win32/Vidar.PAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c6 89 45 f0 8b c6 d3 e8 03 45 d0 89 45 f8 8b 45 f0 31 45 fc 8b 45 f8 31 45 fc 89 1d ?? ?? ?? ?? 8b 45 fc 29 45 f4 8d 45 e4 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Vidar_PAN_MTB_2{
	meta:
		description = "Trojan:Win32/Vidar.PAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2b f9 8b c7 c1 e0 04 03 45 e8 8b d7 89 45 fc 8b 45 f8 03 c7 c1 ea 05 03 55 ec 50 8d 4d fc c7 05 } //1
		$a_01_1 = {55 8b ec 51 c7 45 fc 02 00 00 00 8b 45 08 01 45 fc 83 6d fc 02 8b 45 fc 31 01 c9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}