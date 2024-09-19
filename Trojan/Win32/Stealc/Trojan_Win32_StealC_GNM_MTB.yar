
rule Trojan_Win32_StealC_GNM_MTB{
	meta:
		description = "Trojan:Win32/StealC.GNM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f8 83 c0 46 89 45 fc 83 6d fc 46 8a 45 fc 30 04 1f 47 3b 7d } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}
rule Trojan_Win32_StealC_GNM_MTB_2{
	meta:
		description = "Trojan:Win32/StealC.GNM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c3 c1 e8 ?? 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b f3 c1 e6 ?? 03 74 24 ?? 8d 0c 1f 33 f1 81 3d ?? ?? ?? ?? 03 0b 00 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}