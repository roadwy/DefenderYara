
rule Trojan_Win32_SpyEyes_PVS_MTB{
	meta:
		description = "Trojan:Win32/SpyEyes.PVS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 45 fc 8d 34 07 e8 90 01 04 30 06 b8 01 00 00 00 29 45 fc 83 7d fc 00 7d 90 00 } //2
		$a_02_1 = {30 04 3e b8 01 00 00 00 29 45 80 8b 75 80 3b f3 7d 90 09 05 00 e8 90 00 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2) >=2
 
}