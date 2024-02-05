
rule Trojan_Win32_Cobaltstrike_DK_MTB{
	meta:
		description = "Trojan:Win32/Cobaltstrike.DK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 4d fc 8d 94 01 90 01 04 8b 45 08 03 10 8b 4d 08 89 11 68 5a 11 00 00 ff 15 90 01 04 05 9c 5b 00 00 8b 55 08 8b 0a 2b c8 8b 55 08 89 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}