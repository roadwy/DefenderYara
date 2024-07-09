
rule Trojan_Win32_Redline_GMY_MTB{
	meta:
		description = "Trojan:Win32/Redline.GMY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 d8 88 45 ?? 0f b6 4d ?? f7 d1 88 4d ?? 0f b6 55 ?? 03 55 ?? 88 55 ?? 0f b6 45 ?? f7 d0 88 45 ?? 0f b6 4d ?? 03 4d ?? 88 4d ?? 8b 55 ?? 8a 45 ?? 88 44 15 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}