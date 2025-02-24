
rule Trojan_Win32_LummaC_NLD_MTB{
	meta:
		description = "Trojan:Win32/LummaC.NLD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {83 ec 04 8b 4d f0 8b 45 0c 89 04 24 e8 46 00 00 00 83 ec 04 8b 4d fc 31 e9 } //2
		$a_01_1 = {8b 45 ec c6 40 76 01 8b 4d fc 31 e9 e8 a4 76 00 00 8b 45 ec 89 ec 5d } //1
		$a_03_2 = {55 89 e5 83 ec 28 8b 45 08 89 45 e0 89 45 e4 8b 45 10 8b 45 0c a1 ?? ?? ?? ?? 31 e8 89 45 fc 8b 45 10 8d 4d ec 89 04 24 } //1
		$a_03_3 = {55 89 e5 83 ec 14 8b 45 08 a1 ?? ?? ?? ?? 31 e8 89 45 fc 89 4d f4 8b 4d f4 89 4d f0 8b 45 08 89 45 f8 8d 45 f8 89 04 24 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=5
 
}