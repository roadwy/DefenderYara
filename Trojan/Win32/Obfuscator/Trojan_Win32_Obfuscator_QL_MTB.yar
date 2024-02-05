
rule Trojan_Win32_Obfuscator_QL_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.QL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 45 0c 89 45 fc 8b 0d 90 01 04 89 4d 08 8b 55 08 8b 02 8b 4d fc 8d 94 01 90 01 04 8b 45 08 89 10 8b 4d 08 8b 11 81 ea 90 01 04 8b 45 08 89 10 8b e5 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}