
rule Trojan_Win32_Gandcrab_CS_eml{
	meta:
		description = "Trojan:Win32/Gandcrab.CS!eml,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 00 6a 00 ff 15 90 02 02 60 40 00 a1 90 01 01 f8 40 00 03 85 90 01 04 8b 0d 90 01 04 03 8d 90 01 04 8a 89 3d 34 03 00 88 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}