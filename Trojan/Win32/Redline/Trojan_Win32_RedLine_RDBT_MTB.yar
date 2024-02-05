
rule Trojan_Win32_RedLine_RDBT_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RDBT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 44 24 14 90 01 44 24 1c 8b 44 24 1c 89 44 24 20 8b 4c 24 14 c1 e9 05 89 4c 24 24 8b cb } //00 00 
	condition:
		any of ($a_*)
 
}