
rule Trojan_Win64_Sirefef_Y{
	meta:
		description = "Trojan:Win64/Sirefef.Y,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4d 54 48 8b f8 49 8b 90 01 01 f3 a4 0f b7 55 14 44 0f b7 4d 06 90 00 } //1
		$a_01_1 = {70 32 70 2e 36 34 2e 64 6c 6c } //1 p2p.64.dll
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win64_Sirefef_Y_2{
	meta:
		description = "Trojan:Win64/Sirefef.Y,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4d 54 48 8b f8 49 8b 90 01 01 f3 a4 0f b7 55 14 44 0f b7 4d 06 90 00 } //1
		$a_01_1 = {70 32 70 2e 36 34 2e 64 6c 6c } //1 p2p.64.dll
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}