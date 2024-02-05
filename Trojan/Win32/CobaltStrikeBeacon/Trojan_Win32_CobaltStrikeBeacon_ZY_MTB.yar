
rule Trojan_Win32_CobaltStrikeBeacon_ZY_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrikeBeacon.ZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 d1 83 e1 07 8a 0c 08 30 0c 16 42 83 fa 40 75 ef 31 d2 3b 55 0c 7d 0e 89 d1 83 e1 07 8a 0c 08 30 0c 13 42 eb ed } //00 00 
	condition:
		any of ($a_*)
 
}