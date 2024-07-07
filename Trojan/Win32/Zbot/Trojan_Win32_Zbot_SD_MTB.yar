
rule Trojan_Win32_Zbot_SD_MTB{
	meta:
		description = "Trojan:Win32/Zbot.SD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 49 00 03 f8 8b ff 8b 17 8b 4d 90 01 01 81 f1 9d 10 e6 3d 03 f9 8b 07 c1 c0 05 83 e0 05 03 d0 4e 89 13 b9 4e 2e dc 06 81 f1 4a 2e dc 06 03 d9 85 f6 0f 84 90 01 04 8b 17 8b 4d fc 81 e9 f5 f0 2b ee 03 f9 8b 07 c1 c0 05 83 e0 05 03 d0 4e 89 13 b9 40 00 00 00 c1 c1 1c 03 d9 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}