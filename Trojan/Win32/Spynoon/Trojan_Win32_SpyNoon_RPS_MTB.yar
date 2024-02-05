
rule Trojan_Win32_SpyNoon_RPS_MTB{
	meta:
		description = "Trojan:Win32/SpyNoon.RPS!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 55 f8 03 55 fc 88 0a 8b 45 f8 03 45 fc 8a 08 80 e9 01 8b 55 f8 03 55 fc 88 0a e9 } //00 00 
	condition:
		any of ($a_*)
 
}