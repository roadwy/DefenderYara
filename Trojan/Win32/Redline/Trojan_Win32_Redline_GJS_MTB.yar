
rule Trojan_Win32_Redline_GJS_MTB{
	meta:
		description = "Trojan:Win32/Redline.GJS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {3c d3 40 00 c7 45 ?? 35 45 00 00 c7 85 ?? ?? ?? ?? 48 d3 40 00 c6 45 ?? 77 c7 85 ?? ?? ?? ?? 60 d3 40 00 c7 85 ?? ?? ?? ?? 68 09 00 00 c7 85 ?? ?? ?? ?? 7c d3 40 00 b9 af 6e 00 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_GJS_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GJS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c8 f7 ea 8d 04 0a c1 f8 ?? 89 c2 89 c8 c1 f8 ?? 29 c2 89 d0 89 c2 89 d0 c1 e0 ?? 01 d0 01 c0 01 d0 89 c1 8b 55 f0 8b 45 0c 01 d0 31 cb 89 da 88 10 83 45 f0 01 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}