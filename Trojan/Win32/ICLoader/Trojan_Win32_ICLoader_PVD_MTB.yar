
rule Trojan_Win32_ICLoader_PVD_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.PVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {31 7c 24 10 8b f5 c1 ee 05 03 74 24 34 81 3d ?? ?? ?? ?? b4 11 00 00 75 90 09 0a 00 c7 05 } //2
		$a_02_1 = {8b 45 08 8d 34 07 e8 ?? ?? ?? ?? 30 06 83 65 fc 00 c1 eb 09 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2) >=2
 
}