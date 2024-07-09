
rule Trojan_Win32_Copack_RPY_MTB{
	meta:
		description = "Trojan:Win32/Copack.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {5a 31 08 42 09 d3 40 4a 39 f8 75 e3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Copack_RPY_MTB_2{
	meta:
		description = "Trojan:Win32/Copack.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4a 31 39 01 d3 4a 41 42 89 da 89 d2 39 c1 75 d8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Copack_RPY_MTB_3{
	meta:
		description = "Trojan:Win32/Copack.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 f8 09 ff e8 1c 00 00 00 29 c0 81 e8 01 00 00 00 31 16 81 e8 ?? ?? ?? ?? 46 01 c7 39 de 75 db 89 f8 29 c0 c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}