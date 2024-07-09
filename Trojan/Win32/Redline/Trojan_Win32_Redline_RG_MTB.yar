
rule Trojan_Win32_Redline_RG_MTB{
	meta:
		description = "Trojan:Win32/Redline.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 7c 24 3c 8d 5c 24 2c 8b f7 81 f6 6c 03 00 00 83 7c 24 40 10 0f 43 5c 24 2c 53 c1 ef 02 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Redline_RG_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 8b 4d 08 8b c6 83 c4 08 f7 75 10 8a 3c 0e 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8a 82 ?? ?? ?? ?? 32 c3 02 c7 88 04 0e } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}