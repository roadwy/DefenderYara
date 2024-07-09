
rule Trojan_Win32_Redline_CXL_MTB{
	meta:
		description = "Trojan:Win32/Redline.CXL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 ?? 03 c5 89 44 24 14 8b 44 24 1c 31 44 24 10 8b 4c 24 10 33 4c 24 14 8d 44 24 28 89 4c 24 10 e8 ?? ?? ?? ?? 8d 44 24 24 e8 ?? ?? ?? ?? 83 ef 01 8b 4c 24 28 0f } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}