
rule Trojan_Win32_Zenpak_GNQ_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GNQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 e0 50 8f 05 90 01 04 01 c2 b9 90 01 06 8d 05 90 01 04 89 18 31 c2 83 c2 90 01 01 29 c2 89 2d 90 01 04 42 8d 05 90 01 04 89 30 e8 90 01 04 40 4a ba 90 01 04 31 3d 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}