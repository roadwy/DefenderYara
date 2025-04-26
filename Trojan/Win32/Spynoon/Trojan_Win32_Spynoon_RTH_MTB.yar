
rule Trojan_Win32_Spynoon_RTH_MTB{
	meta:
		description = "Trojan:Win32/Spynoon.RTH!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 c1 92 ab 00 00 05 25 7f 00 00 48 f7 d3 81 e2 14 0c 01 00 f7 d1 58 b9 14 c4 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}