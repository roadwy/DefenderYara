
rule Trojan_Win32_Zusy_AHK_MTB{
	meta:
		description = "Trojan:Win32/Zusy.AHK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 04 00 00 "
		
	strings :
		$a_03_0 = {88 df 0f b6 fb 80 c7 ?? 80 fb ?? 0f b6 df 0f 42 df 89 f7 c1 e7 ?? 01 f7 0f b6 f3 01 fe eb } //30
		$a_03_1 = {89 55 f0 8b 30 f7 d1 d3 e3 4b 8b 8e ?? ?? ?? ?? 8d 46 ?? 89 45 e8 8d 86 ?? ?? ?? ?? 89 45 ec } //30
		$a_01_2 = {f2 0f 10 45 c0 f2 0f 10 4d c8 8d 4d e4 f2 0f 11 49 08 f2 0f 11 01 8d 45 9c } //20
		$a_01_3 = {8b 4d ec 8b 55 f0 89 75 e0 89 11 89 45 e4 89 4d e8 8b 4d 08 c7 45 ec } //20
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*30+(#a_01_2  & 1)*20+(#a_01_3  & 1)*20) >=50
 
}