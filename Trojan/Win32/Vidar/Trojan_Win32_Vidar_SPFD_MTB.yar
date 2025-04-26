
rule Trojan_Win32_Vidar_SPFD_MTB{
	meta:
		description = "Trojan:Win32/Vidar.SPFD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d dc 30 04 31 83 ff 0f } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win32_Vidar_SPFD_MTB_2{
	meta:
		description = "Trojan:Win32/Vidar.SPFD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 04 8d 80 f0 42 00 8b f0 81 e6 ff 00 00 00 c1 e8 08 33 04 b5 80 f4 42 00 41 89 04 8d 7c f4 42 00 3b ca } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}