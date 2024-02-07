
rule Trojan_Win32_Houyek_A{
	meta:
		description = "Trojan:Win32/Houyek.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {00 52 65 63 65 69 76 65 72 20 4c 61 73 74 20 4e 61 6d 65 3a } //01 00 
		$a_00_1 = {3c 2f 63 69 74 79 3e 00 } //01 00  ⼼楣祴>
		$a_03_2 = {8b 00 8b 40 30 50 e8 90 01 04 8d 45 fc 50 6a 1a 8b c3 e8 90 01 04 50 e8 90 01 04 8d 85 90 01 01 fe ff ff 50 8b 45 fc 50 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}