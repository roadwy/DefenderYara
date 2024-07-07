
rule Trojan_Win32_Zenpak_GNR_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GNR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {42 29 c2 29 c2 8d 05 90 01 04 31 38 31 c2 31 d0 89 35 90 01 04 83 c2 03 83 f2 08 01 2d 90 01 04 40 29 d0 31 d0 8d 05 90 01 04 89 18 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}