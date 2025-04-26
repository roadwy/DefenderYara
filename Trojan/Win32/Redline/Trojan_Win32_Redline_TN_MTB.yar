
rule Trojan_Win32_Redline_TN_MTB{
	meta:
		description = "Trojan:Win32/Redline.TN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 c0 29 c8 88 45 ?? 8b 4d ?? 0f b6 45 ?? 31 c8 88 45 ?? 0f b6 45 ?? 2d ?? ?? ?? ?? 88 45 ?? 8a 4d ?? 8b 45 ?? 88 4c 05 ?? 8b 45 ?? 83 c0 ?? 89 45 ?? e9 } //1
		$a_03_1 = {83 f0 4b 88 45 ?? 8b 4d ?? 0f b6 45 ?? 29 c8 88 45 ?? 0f b6 45 ?? 83 f0 ?? 88 45 ?? 8b 4d ?? 0f b6 45 ?? 29 c8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}