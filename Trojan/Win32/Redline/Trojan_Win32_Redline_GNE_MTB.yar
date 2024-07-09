
rule Trojan_Win32_Redline_GNE_MTB{
	meta:
		description = "Trojan:Win32/Redline.GNE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 7d 08 f6 17 80 07 ?? 80 2f ?? 47 e2 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_GNE_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GNE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {88 55 db 0f b6 4d ?? 03 4d dc 88 4d ?? 0f b6 55 ?? c1 fa ?? 0f b6 45 ?? c1 e0 ?? 0b d0 88 55 ?? 0f b6 4d ?? 03 4d ?? 88 4d ?? 8b 55 ?? 8a 45 ?? 88 44 15 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_GNE_MTB_3{
	meta:
		description = "Trojan:Win32/Redline.GNE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 d2 88 55 ?? 0f b6 45 ?? 83 c0 ?? 88 45 ?? 0f b6 4d ?? f7 d1 88 4d ?? 0f b6 55 ?? d1 fa 0f b6 45 ?? c1 e0 ?? 0b d0 88 55 ?? 8b 4d ?? 8a 55 ?? 88 54 0d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}