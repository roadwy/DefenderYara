
rule Trojan_Win32_SpyNoon_RPW_MTB{
	meta:
		description = "Trojan:Win32/SpyNoon.RPW!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 c1 ed 00 00 00 8b 55 f8 03 55 fc 88 0a e9 54 fe ff ff 8b 45 f8 ff e0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}