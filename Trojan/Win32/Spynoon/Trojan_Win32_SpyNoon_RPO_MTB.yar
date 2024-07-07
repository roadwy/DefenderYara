
rule Trojan_Win32_SpyNoon_RPO_MTB{
	meta:
		description = "Trojan:Win32/SpyNoon.RPO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4d f0 80 34 01 90 01 01 8b 4d f0 80 04 01 90 01 01 8b 4d f0 80 04 01 90 01 01 8b 4d f0 80 04 01 90 01 01 8b 4d f0 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}