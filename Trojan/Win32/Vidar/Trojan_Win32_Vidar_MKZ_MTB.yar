
rule Trojan_Win32_Vidar_MKZ_MTB{
	meta:
		description = "Trojan:Win32/Vidar.MKZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {51 52 89 54 24 ?? ff 15 ?? ?? ?? ?? 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 6a 00 8d 54 24 ?? 52 6a 00 68 ?? ?? ?? ?? 6a 00 6a 00 ff 15 ?? ?? ?? ?? 31 7c 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 8b 15 ?? ?? ?? ?? 81 fa ?? ?? ?? ?? 74 ?? 81 c3 ?? ?? ?? ?? ff 4c 24 ?? 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}