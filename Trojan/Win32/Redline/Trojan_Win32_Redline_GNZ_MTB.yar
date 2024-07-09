
rule Trojan_Win32_Redline_GNZ_MTB{
	meta:
		description = "Trojan:Win32/Redline.GNZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 7d 08 33 c0 f6 17 80 37 ?? 47 e2 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_GNZ_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GNZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 84 34 ?? ?? ?? ?? 8b 4c 24 10 03 c2 0f b6 c0 0f b6 84 04 ?? ?? ?? ?? 30 04 19 43 3b dd } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}