
rule Trojan_Win32_IcedId_SIBP_MTB{
	meta:
		description = "Trojan:Win32/IcedId.SIBP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 00 75 00 67 00 67 00 65 00 73 00 74 00 73 00 74 00 65 00 70 00 } //01 00  Suggeststep
		$a_03_1 = {04 ff 4c 24 90 01 01 90 02 10 90 18 90 02 b0 8b 54 24 90 01 01 8b 12 90 02 30 8b 7c 24 90 01 01 81 c2 90 01 04 89 17 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}