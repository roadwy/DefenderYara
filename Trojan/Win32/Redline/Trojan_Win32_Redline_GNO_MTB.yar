
rule Trojan_Win32_Redline_GNO_MTB{
	meta:
		description = "Trojan:Win32/Redline.GNO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 d2 88 55 ?? 0f b6 45 ?? f7 d8 88 45 ?? 0f b6 4d ?? 83 e9 ?? 88 4d ?? 0f b6 55 ?? f7 da 88 55 ?? 8b 45 ?? 8a 4d ?? 88 4c 05 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}