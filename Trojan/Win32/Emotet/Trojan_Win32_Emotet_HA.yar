
rule Trojan_Win32_Emotet_HA{
	meta:
		description = "Trojan:Win32/Emotet.HA,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 4d 41 4c 70 4f 56 49 36 49 75 69 2e 70 64 62 } //01 00 
		$a_01_1 = {44 6d 4d 67 4d 66 78 76 73 72 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}