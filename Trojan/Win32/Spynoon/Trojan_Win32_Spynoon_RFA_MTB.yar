
rule Trojan_Win32_Spynoon_RFA_MTB{
	meta:
		description = "Trojan:Win32/Spynoon.RFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 e1 0f 00 00 00 81 c1 00 00 00 00 8a 14 08 88 55 90 01 01 8a 55 90 01 01 8b 45 90 01 01 8b 4d 90 01 01 8b 75 90 01 01 89 34 24 89 4c 24 90 01 01 89 44 24 90 01 01 0f b6 c2 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}