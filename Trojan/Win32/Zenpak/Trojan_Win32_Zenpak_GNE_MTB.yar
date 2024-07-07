
rule Trojan_Win32_Zenpak_GNE_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GNE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 20 31 c2 4a 4a 83 f0 90 01 01 e8 90 01 04 c3 01 c2 89 f0 50 8f 05 90 01 04 31 d0 31 d0 89 2d 90 01 04 e8 90 01 04 29 d0 89 f8 50 8f 05 90 01 04 8d 05 90 01 04 31 18 b9 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}