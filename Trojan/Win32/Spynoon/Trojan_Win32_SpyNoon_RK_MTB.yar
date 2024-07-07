
rule Trojan_Win32_SpyNoon_RK_MTB{
	meta:
		description = "Trojan:Win32/SpyNoon.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 08 85 c0 74 1a 83 c0 fe 85 c0 7c 10 8a 54 08 01 32 14 08 80 f2 78 88 14 08 48 79 f0 80 31 6d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}