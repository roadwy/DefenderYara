
rule Trojan_Win32_Emotet_BV{
	meta:
		description = "Trojan:Win32/Emotet.BV,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 65 23 40 31 2e 50 64 62 } //01 00 
		$a_01_1 = {59 00 55 00 51 00 39 00 46 00 2a 00 6d 00 69 00 4f 00 71 00 } //00 00 
	condition:
		any of ($a_*)
 
}