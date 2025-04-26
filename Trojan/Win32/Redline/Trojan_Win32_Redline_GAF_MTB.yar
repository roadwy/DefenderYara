
rule Trojan_Win32_Redline_GAF_MTB{
	meta:
		description = "Trojan:Win32/Redline.GAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 d8 88 45 ?? 0f b6 4d ?? 83 e9 ?? 88 4d ?? 0f b6 55 ?? f7 da 88 55 ?? 0f b6 45 ?? d1 f8 0f b6 4d ?? c1 e1 ?? 0b c1 88 45 ?? 0f b6 55 ?? 2b 55 ?? 88 55 ?? 8b 45 ?? 8a 4d ?? 88 4c 05 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}