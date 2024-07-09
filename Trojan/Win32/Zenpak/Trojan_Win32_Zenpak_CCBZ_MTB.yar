
rule Trojan_Win32_Zenpak_CCBZ_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.CCBZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 d3 01 fb 8b 3b 69 d8 ?? ?? ?? ?? 01 da 81 c2 ?? ?? ?? ?? 0f b7 12 31 f2 8b b5 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}