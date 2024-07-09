
rule Trojan_Win32_Redline_MKL_MTB{
	meta:
		description = "Trojan:Win32/Redline.MKL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 c4 0c 8b 45 ?? 03 45 ?? 8a 08 88 4d ?? 0f b6 4d ?? 8b 45 ?? 33 d2 f7 75 } //1
		$a_03_1 = {8a 45 ee 88 45 ?? 0f b6 4d ?? 8b 55 ?? 03 55 ?? 0f b6 02 2b c1 8b 4d ?? 03 4d ?? 88 01 e9 ?? ?? ?? ?? 8b 4d ?? 33 cd e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}