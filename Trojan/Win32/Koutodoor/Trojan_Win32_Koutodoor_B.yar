
rule Trojan_Win32_Koutodoor_B{
	meta:
		description = "Trojan:Win32/Koutodoor.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {f7 7d 0c 8b 45 08 32 0c 02 } //1
		$a_01_1 = {81 7d e8 10 84 00 00 74 1c } //1
		$a_03_2 = {3d 20 04 00 00 74 0d ff d7 3d 22 04 00 00 74 04 33 ?? eb 05 } //1
		$a_03_3 = {44 50 00 00 90 09 03 00 c7 45 ?? ?? ?? ?? ?? c7 45 ?? 45 50 00 00 c7 45 ?? 3d 50 00 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*2) >=3
 
}