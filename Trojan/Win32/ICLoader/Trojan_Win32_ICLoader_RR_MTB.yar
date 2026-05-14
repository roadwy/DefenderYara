
rule Trojan_Win32_ICLoader_RR_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c2 88 5e 08 25 ff 00 00 00 33 d8 89 5d e4 8b 0e 8b 45 dc 8b 56 04 89 06 8b 45 e0 89 4d dc 89 46 04 8b 4e 08 8b 46 08 c1 e1 17 33 c3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}