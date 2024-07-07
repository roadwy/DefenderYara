
rule Trojan_Win32_Raccoon_WE_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.WE!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d f8 8b 5d fc 8b d1 c1 e2 04 8b c1 c1 e8 05 03 45 e4 03 d7 03 d9 33 d3 33 d0 89 55 ec } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}