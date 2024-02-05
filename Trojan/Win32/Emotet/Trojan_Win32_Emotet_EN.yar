
rule Trojan_Win32_Emotet_EN{
	meta:
		description = "Trojan:Win32/Emotet.EN,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {6c 00 6b 00 77 00 72 00 6c 00 6a 00 48 00 4b 00 4c 00 32 00 33 00 6b 00 6c 00 68 00 6a 00 3b 00 6d 00 65 00 74 00 6b 00 } //00 00 
	condition:
		any of ($a_*)
 
}