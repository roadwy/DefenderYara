
rule Trojan_Win32_Raccoon_MV_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.MV!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 00 47 86 c8 61 c3 81 00 eb 34 ef c6 c3 01 08 c3 29 08 c3 } //5
		$a_01_1 = {c7 45 f4 02 00 00 00 83 45 f4 03 8b 8d 24 fd ff ff 8b c2 c1 e0 04 89 85 2c fd ff ff } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}