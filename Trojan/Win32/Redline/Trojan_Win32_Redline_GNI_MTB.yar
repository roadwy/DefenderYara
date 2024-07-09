
rule Trojan_Win32_Redline_GNI_MTB{
	meta:
		description = "Trojan:Win32/Redline.GNI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 7d 08 33 c0 f6 17 80 2f ?? 80 07 ?? 47 e2 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_GNI_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GNI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 00 ff d6 80 04 2f ?? 68 } //10
		$a_03_1 = {6a 00 ff d6 80 34 2f ?? 68 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}
rule Trojan_Win32_Redline_GNI_MTB_3{
	meta:
		description = "Trojan:Win32/Redline.GNI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c1 c1 e8 ?? 03 44 24 ?? 03 cb 33 c2 33 c1 2b f0 8b d6 c1 e2 ?? 89 44 24 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 81 3d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}