
rule Trojan_Win32_Redline_GMZ_MTB{
	meta:
		description = "Trojan:Win32/Redline.GMZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 80 34 03 ?? ff d7 6a 00 ff d6 8b 44 24 ?? 6a 00 6a 00 80 34 03 ?? ff d7 6a 00 ff d6 8b 44 24 ?? 6a 00 6a 00 80 04 03 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_GMZ_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GMZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b c1 88 45 ?? 0f b6 55 ?? 03 55 ?? 88 55 ?? 0f b6 45 ?? f7 d8 88 45 ?? 0f b6 4d ?? c1 f9 ?? 0f b6 55 ?? c1 e2 ?? 0b ca 88 4d ?? 0f b6 45 ?? 03 45 ?? 88 45 ?? 8b 4d ?? 8a 55 ?? 88 54 0d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}