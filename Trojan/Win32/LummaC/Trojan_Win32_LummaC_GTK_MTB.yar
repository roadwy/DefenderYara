
rule Trojan_Win32_LummaC_GTK_MTB{
	meta:
		description = "Trojan:Win32/LummaC.GTK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 8c 04 ?? ?? ?? ?? 31 c1 89 ca 83 f2 ?? 83 e1 37 01 c9 29 d1 88 8c 04 ?? ?? ?? ?? 40 3d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_LummaC_GTK_MTB_2{
	meta:
		description = "Trojan:Win32/LummaC.GTK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 8c 0d ?? ?? ?? ?? 8b 55 ?? 03 55 ?? 0f b6 02 33 c1 8b 4d ?? 03 4d ?? 88 01 50 33 c0 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_LummaC_GTK_MTB_3{
	meta:
		description = "Trojan:Win32/LummaC.GTK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {88 5b 00 00 2b c1 33 d0 0f af 95 } //5
		$a_03_1 = {6a 40 68 00 30 00 00 8b 85 ?? ?? ?? ?? 50 6a 00 ff 95 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? c7 85 ?? ?? ?? ?? d0 f9 82 20 83 bd } //5
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}
rule Trojan_Win32_LummaC_GTK_MTB_4{
	meta:
		description = "Trojan:Win32/LummaC.GTK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 84 05 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 0f b6 8c 0d ?? ?? ?? ?? 01 c8 b9 00 01 00 00 99 f7 f9 89 95 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 0f b6 b4 05 ?? ?? ?? ?? 8b 45 08 8b 8d ?? ?? ?? ?? 0f b6 14 08 31 f2 88 14 08 8b 85 ?? ?? ?? ?? 83 c0 01 89 85 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}