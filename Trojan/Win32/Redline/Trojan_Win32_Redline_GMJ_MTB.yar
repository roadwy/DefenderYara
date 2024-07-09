
rule Trojan_Win32_Redline_GMJ_MTB{
	meta:
		description = "Trojan:Win32/Redline.GMJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 2b f7 f7 e9 c1 ee de 66 c1 d8 35 66 f7 e8 81 f7 ed 02 00 00 66 c1 df 44 8b 75 c4 8b 4d dc 8b 55 d8 8b 46 24 8d 04 48 0f b7 0c 10 8b 46 1c 8d 04 88 8b 4d f8 8b 04 10 89 45 d4 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_GMJ_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GMJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {d1 e2 0b ca 88 8d ?? ?? ?? ?? 0f b6 85 ?? ?? ?? ?? 2d 98 00 00 00 88 85 ?? ?? ?? ?? 0f b6 8d ?? ?? ?? ?? f7 d1 88 8d ?? ?? ?? ?? 0f b6 95 ?? ?? ?? ?? 81 c2 d8 00 00 00 88 95 ?? ?? ?? ?? 0f b6 85 ?? ?? ?? ?? f7 d0 88 85 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 8a 95 ?? ?? ?? ?? 88 94 0d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}