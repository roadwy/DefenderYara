
rule Trojan_Win32_Redline_TZ_MTB{
	meta:
		description = "Trojan:Win32/Redline.TZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 8b 45 08 8b 4d 0c 31 08 5d } //1
		$a_03_1 = {8b 45 dc 8d 0c 07 33 4d ?? 89 35 ?? ?? ?? ?? 89 4d ?? 8b 45 ?? 01 05 ?? ?? ?? ?? 51 8d 45 ?? 50 e8 ?? ?? ?? ?? 8b 5d ?? 8b fb c1 e7 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}