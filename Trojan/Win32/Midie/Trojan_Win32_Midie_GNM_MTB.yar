
rule Trojan_Win32_Midie_GNM_MTB{
	meta:
		description = "Trojan:Win32/Midie.GNM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 d8 bb 99 00 00 00 ?? 31 c3 80 07 ?? 80 2f ?? ?? 89 d8 bb ?? ?? ?? ?? ?? 31 c3 f6 2f 47 e2 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Midie_GNM_MTB_2{
	meta:
		description = "Trojan:Win32/Midie.GNM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 4d f8 8b 51 40 0f b7 0a 99 f7 f9 83 c2 01 89 55 fc 6a 00 8b 55 fc 69 d2 e8 03 00 00 81 c2 b8 0b 00 00 52 } //5
		$a_03_1 = {6a 00 6a 04 8b 4d 08 83 c1 0c 51 8b 55 d8 52 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? eb } //5
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}