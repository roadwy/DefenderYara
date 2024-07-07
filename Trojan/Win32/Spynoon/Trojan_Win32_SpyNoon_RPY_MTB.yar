
rule Trojan_Win32_SpyNoon_RPY_MTB{
	meta:
		description = "Trojan:Win32/SpyNoon.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 55 f8 03 55 fc 88 0a e9 90 01 02 ff ff 8b 45 f8 ff e0 90 00 } //1
		$a_00_1 = {6a 00 68 80 00 00 00 6a 03 6a 00 6a 07 68 00 00 00 80 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}