
rule Trojan_Win32_Redline_GMK_MTB{
	meta:
		description = "Trojan:Win32/Redline.GMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {30 14 33 83 ff 0f ?? ?? 6a 00 ff d5 6a 2e 8d 44 24 10 6a 00 50 c7 44 24 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_GMK_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c8 f7 e2 89 c8 29 d0 d1 e8 01 d0 c1 e8 ?? 89 c2 c1 e2 ?? 29 c2 89 c8 29 d0 0f b6 84 05 ?? ?? ?? ?? 31 c3 89 da 8b 45 ?? 05 ?? ?? ?? ?? 88 10 83 45 ?? ?? 8b 45 ?? 3d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}