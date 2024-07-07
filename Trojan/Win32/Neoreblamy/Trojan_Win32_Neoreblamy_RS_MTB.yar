
rule Trojan_Win32_Neoreblamy_RS_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.RS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {21 45 f8 ff 31 8b 45 fc 83 c0 0c 68 44 b3 06 10 89 45 fc ff 30 6a 03 68 51 03 00 00 56 e8 8d fd ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Neoreblamy_RS_MTB_2{
	meta:
		description = "Trojan:Win32/Neoreblamy.RS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f be f0 33 d2 0f be c3 03 45 fc 6a 19 59 f7 f1 8b 45 fc 8b ca d3 e6 8b 4d f8 03 ce 40 89 4d f8 89 45 fc 39 47 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}