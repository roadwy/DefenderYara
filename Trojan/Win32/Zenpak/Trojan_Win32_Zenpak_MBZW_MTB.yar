
rule Trojan_Win32_Zenpak_MBZW_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.MBZW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 45 b8 8b 45 b8 33 45 c8 89 45 c8 8b 45 c8 03 45 c4 89 45 c4 8b 45 b4 05 01 00 00 00 89 45 a4 8b 45 a4 89 45 b4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}