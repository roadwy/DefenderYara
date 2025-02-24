
rule Trojan_Win32_Babar_GA_MTB{
	meta:
		description = "Trojan:Win32/Babar.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 55 ec 8b 45 10 01 c2 8d 4d d8 8b 45 ec 01 c8 0f b6 00 88 02 83 45 ec 01 83 7d ec 0f 7e e1 } //1
		$a_01_1 = {01 d0 31 cb 89 da 88 10 83 45 f4 01 0f b6 45 eb 83 c0 01 88 45 eb 80 7d eb 03 76 c7 } //1
		$a_01_2 = {67 65 74 5f 68 6f 73 74 66 78 72 5f 70 61 74 68 } //1 get_hostfxr_path
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}