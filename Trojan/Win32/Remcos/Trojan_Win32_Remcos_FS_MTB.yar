
rule Trojan_Win32_Remcos_FS_MTB{
	meta:
		description = "Trojan:Win32/Remcos.FS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f b6 75 eb 89 f0 05 9d 00 00 00 88 45 eb 0f b6 75 eb c1 fe 05 0f b6 7d eb c1 e7 03 89 f0 09 f8 88 45 eb 8b 75 ec 0f b6 7d eb 89 f8 29 f0 88 45 eb 8a 45 eb 8b 75 ec 88 04 35 90 01 04 8b 45 ec 83 c0 01 89 45 ec e9 90 00 } //1
		$a_03_1 = {0f b6 75 eb 29 f0 88 45 eb 0f b6 75 eb 89 f0 35 ff 00 00 00 88 45 eb 8b 75 ec 0f b6 7d eb 89 f8 29 f0 88 45 eb 0f b6 75 eb 89 f0 83 f0 ff 88 45 eb 8a 45 eb 8b 75 ec 88 04 35 90 01 04 8b 45 ec 83 c0 01 89 45 ec e9 90 00 } //1
		$a_03_2 = {0f b6 7d eb c1 e7 07 89 f0 09 f8 88 45 eb 0f b6 75 eb 89 f0 83 e8 39 88 45 eb 0f b6 75 eb 89 f0 83 f0 59 88 45 eb 8b 75 ec 0f b6 7d eb 89 f8 29 f0 88 45 eb 0f b6 75 eb 89 f0 35 85 00 00 00 88 45 eb 8a 45 eb 8b 75 ec 88 04 35 90 01 04 8b 45 ec 83 c0 01 89 45 ec e9 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}