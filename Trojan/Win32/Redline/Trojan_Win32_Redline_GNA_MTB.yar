
rule Trojan_Win32_Redline_GNA_MTB{
	meta:
		description = "Trojan:Win32/Redline.GNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 7d 08 f6 17 80 07 ?? 47 e2 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_GNA_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c0 80 07 ?? 8b c3 33 c3 33 c0 33 c3 33 d8 8b de 33 c3 33 f6 8b f6 f6 2f 47 e2 } //10
		$a_03_1 = {8b c3 33 de 80 07 ?? 8b c6 33 c0 8b db 8b c6 8b d8 33 c3 33 f6 33 de 33 c3 f6 2f 47 e2 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_GNA_MTB_3{
	meta:
		description = "Trojan:Win32/Redline.GNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 da 88 55 ?? 0f b6 45 ?? f7 d0 88 45 ?? 0f b6 4d ?? f7 d9 88 4d ?? 0f b6 55 ?? 03 55 ?? 88 55 ?? 0f b6 45 ?? f7 d8 88 45 ?? 0f b6 4d ?? 2b 4d ?? 88 4d ?? 8b 55 ?? 8a 45 ?? 88 44 15 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}