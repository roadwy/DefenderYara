
rule Trojan_Win32_Neoreblamy_EM_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {59 59 8b 4d f8 8b 09 03 c1 99 b9 07 ca 9a 3b f7 f9 8b 45 f8 89 10 } //6
	condition:
		((#a_01_0  & 1)*6) >=6
 
}
rule Trojan_Win32_Neoreblamy_EM_MTB_2{
	meta:
		description = "Trojan:Win32/Neoreblamy.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 45 fc 8b 45 fc 89 45 f8 8b 45 f8 8b 4d f8 8b 00 23 41 04 83 f8 ff 74 0a 8b 4d fc 8b 01 8b 51 04 eb 59 8b 45 fc 83 20 00 83 60 04 00 ff 75 0c 8b 45 0c 8b 4d 08 } //6
	condition:
		((#a_01_0  & 1)*6) >=6
 
}