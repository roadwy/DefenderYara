
rule Trojan_Win32_Neoreblamy_EC_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 d2 8b c6 6a 34 59 f7 f1 8b 45 08 8b 0c b3 8b 14 90 8b c1 23 c2 03 c0 2b c8 03 ca 89 0c b3 46 3b f7 72 dc } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Neoreblamy_EC_MTB_2{
	meta:
		description = "Trojan:Win32/Neoreblamy.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 14 01 8d 48 11 8a c1 22 c2 02 c0 2a c8 0f be c2 03 45 fc 02 ca 0f be f1 33 d2 6a 19 59 f7 f1 8b 45 fc 8b ca d3 e6 8b 4d f8 03 ce 40 89 4d f8 89 45 fc } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}