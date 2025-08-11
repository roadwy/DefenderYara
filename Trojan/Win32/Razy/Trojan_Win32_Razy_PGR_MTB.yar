
rule Trojan_Win32_Razy_PGR_MTB{
	meta:
		description = "Trojan:Win32/Razy.PGR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 ec 04 c7 04 24 ?? ?? ?? ?? 59 09 f6 ?? ?? ?? ?? ?? 31 10 81 c0 ?? ?? ?? ?? 46 39 d8 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_Win32_Razy_PGR_MTB_2{
	meta:
		description = "Trojan:Win32/Razy.PGR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 bb e0 2c 8d 15 ?? ?? ?? ?? 87 cb c1 db 0a 89 d7 ?? 33 f7 c1 e3 0d 33 d8 81 f2 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_Win32_Razy_PGR_MTB_3{
	meta:
		description = "Trojan:Win32/Razy.PGR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 4d b4 8a 10 8b 45 e8 89 c1 81 c1 ?? ?? ?? ?? 89 4d e8 8a 75 cb 80 c6 4f 88 75 cb 88 10 8b 45 d8 8b 4d b0 01 c8 89 45 d8 eb } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}