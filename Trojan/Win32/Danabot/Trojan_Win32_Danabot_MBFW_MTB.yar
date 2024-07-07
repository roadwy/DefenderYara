
rule Trojan_Win32_Danabot_MBFW_MTB{
	meta:
		description = "Trojan:Win32/Danabot.MBFW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 03 45 90 01 01 89 45 90 01 01 89 45 90 01 01 8d 04 33 33 d0 81 3d 90 00 } //1
		$a_01_1 = {33 d0 8b cf 89 55 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Danabot_MBFW_MTB_2{
	meta:
		description = "Trojan:Win32/Danabot.MBFW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 45 d0 89 45 ec 8b 45 f8 89 45 f0 8b 45 e8 01 45 fc 8b 45 fc 31 45 f0 } //1
		$a_03_1 = {8b 45 f8 8b 55 f4 33 45 ec 81 c3 90 01 04 8b 4d dc 2b f0 89 45 f8 89 75 fc 4f 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}