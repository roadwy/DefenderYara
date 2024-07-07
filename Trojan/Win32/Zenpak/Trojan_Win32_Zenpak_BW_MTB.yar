
rule Trojan_Win32_Zenpak_BW_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.BW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 e5 8a 45 90 01 01 8a 4d 08 c7 05 90 01 08 8b 15 90 01 04 81 c2 90 01 04 89 15 90 01 04 30 c8 0f b6 c0 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}