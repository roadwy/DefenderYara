
rule Trojan_Win32_Fauppod_GNT_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.GNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 55 14 68 ?? ?? ?? ?? 83 c4 04 80 3a 00 ?? ?? ?? ?? ac 32 02 47 88 47 ff 68 ?? ?? ?? ?? 83 c4 04 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 42 83 e9 01 85 c9 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Fauppod_GNT_MTB_2{
	meta:
		description = "Trojan:Win32/Fauppod.GNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 83 c6 01 8a 46 ff ?? 32 02 ?? 47 88 47 ff } //10
		$a_03_1 = {83 c4 04 42 89 c0 89 c0 83 e9 01 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 85 c9 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}