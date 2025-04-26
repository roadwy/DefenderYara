
rule Trojan_Win32_Redline_UR_MTB{
	meta:
		description = "Trojan:Win32/Redline.UR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 d3 e8 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 33 44 24 ?? 89 7c 24 ?? 89 44 24 ?? 89 44 24 ?? 8b 44 24 ?? 89 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 4c 24 ?? 89 4c 24 ?? 89 3d ?? ?? ?? ?? 8b 44 24 ?? 29 44 24 ?? 81 44 24 ?? 47 86 c8 61 ff 4c 24 ?? 0f 85 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}