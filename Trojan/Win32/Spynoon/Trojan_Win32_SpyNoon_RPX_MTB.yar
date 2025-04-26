
rule Trojan_Win32_SpyNoon_RPX_MTB{
	meta:
		description = "Trojan:Win32/SpyNoon.RPX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 c3 82 18 00 00 81 c1 ee 8c 00 00 81 ea ed 1c 01 00 2d 03 51 01 00 ba 7b 4f 01 00 81 e3 85 69 01 00 4a c2 3f e4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}