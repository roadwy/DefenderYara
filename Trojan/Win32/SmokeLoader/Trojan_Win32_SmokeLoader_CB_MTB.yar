
rule Trojan_Win32_SmokeLoader_CB_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 78 8b 4d 7c 31 08 83 c5 70 c9 c2 08 00 55 8b ec 8b 4d 08 8b 01 89 45 08 8b 45 0c 01 45 08 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win32_SmokeLoader_CB_MTB_2{
	meta:
		description = "Trojan:Win32/SmokeLoader.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {01 7c 24 10 89 6c 24 24 8b 44 24 2c 01 44 24 24 8b 44 24 3c 90 01 44 24 24 8b 44 24 24 89 44 24 1c } //2
		$a_03_1 = {8b 4c 24 20 8b c6 d3 e8 8b 4c 24 1c 31 4c 24 10 03 c3 81 3d 90 02 04 21 01 00 00 89 44 24 14 75 90 00 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}