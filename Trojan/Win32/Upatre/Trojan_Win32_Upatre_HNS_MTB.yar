
rule Trojan_Win32_Upatre_HNS_MTB{
	meta:
		description = "Trojan:Win32/Upatre.HNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {c5 00 2c 86 08 d0 14 4a 4a c3 f2 ee 45 15 64 23 3d e0 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Upatre_HNS_MTB_2{
	meta:
		description = "Trojan:Win32/Upatre.HNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 14 96 89 14 81 eb db 8b 45 f8 c1 e0 02 89 45 fc 8b 4d fc 89 4d f0 eb 09 8b 55 f0 83 c2 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}