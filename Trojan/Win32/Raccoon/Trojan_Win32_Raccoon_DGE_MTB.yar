
rule Trojan_Win32_Raccoon_DGE_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.DGE!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {c1 e1 04 03 4d e0 8b c3 c1 e8 05 03 45 e4 8d 14 1f 33 ca 33 c8 29 4d f4 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}