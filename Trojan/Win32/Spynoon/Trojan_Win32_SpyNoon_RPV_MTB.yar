
rule Trojan_Win32_SpyNoon_RPV_MTB{
	meta:
		description = "Trojan:Win32/SpyNoon.RPV!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {35 c4 00 00 00 8b 4d f8 03 4d fc 88 01 e9 be fe ff ff 8b 45 f8 ff e0 } //00 00 
	condition:
		any of ($a_*)
 
}