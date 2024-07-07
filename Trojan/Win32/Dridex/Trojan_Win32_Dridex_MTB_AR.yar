
rule Trojan_Win32_Dridex_MTB_AR{
	meta:
		description = "Trojan:Win32/Dridex!MTB.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 0c 96 89 5c 24 10 66 89 1d 90 01 04 8d 1c 4d 74 7b fe ff 89 1d 90 01 04 8b 4c 24 0c 81 c7 30 50 07 01 8b f2 89 3d 90 01 04 2b f0 83 c6 33 89 39 8b 4c 24 10 0f b7 c9 83 e9 01 74 90 00 } //1
		$a_01_1 = {00 c4 8b 54 24 10 8a 04 0a 04 cf 28 e0 8b 74 24 0c 88 04 0e } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}