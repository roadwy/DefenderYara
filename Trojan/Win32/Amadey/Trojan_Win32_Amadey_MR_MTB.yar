
rule Trojan_Win32_Amadey_MR_MTB{
	meta:
		description = "Trojan:Win32/Amadey.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b ec 56 68 e4 5e 4a 00 68 dc 5e 4a 00 68 24 36 4a 00 6a 21 } //15
		$a_03_1 = {89 4d fc 8b 45 fc 89 45 f8 8b 45 fc 0f b6 00 85 c0 74 ?? 83 3d 44 51 4b 00 00 ?? ?? ff 15 4c 90 90 49 00 39 05 44 51 4b 00 } //10
	condition:
		((#a_01_0  & 1)*15+(#a_03_1  & 1)*10) >=25
 
}