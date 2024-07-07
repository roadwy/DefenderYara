
rule Trojan_Win32_Zenpak_GNW_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GNW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 d0 01 25 90 01 04 48 e8 90 01 04 4a 42 8d 05 90 01 04 31 30 29 d0 31 1d 90 01 04 e8 90 01 04 31 d0 31 2d 90 01 04 83 c2 0a b8 03 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}