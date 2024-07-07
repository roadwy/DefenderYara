
rule Trojan_Win32_Amadey_RPY_MTB{
	meta:
		description = "Trojan:Win32/Amadey.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c9 33 db 33 d2 8b 45 08 8a 10 80 ca 60 03 da d1 e3 03 45 10 8a 08 84 c9 e0 ee 33 c0 8b 4d 0c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Amadey_RPY_MTB_2{
	meta:
		description = "Trojan:Win32/Amadey.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {1d b0 00 00 00 f7 ee 81 ce b8 00 00 00 33 c9 33 ff 48 83 de 09 25 e0 00 00 00 f7 d0 c1 ca e9 81 df e0 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}