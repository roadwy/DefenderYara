
rule Trojan_Win32_Redline_CAFD_MTB{
	meta:
		description = "Trojan:Win32/Redline.CAFD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 1c 0e 8b c6 83 e0 90 01 01 8a 80 90 01 04 32 c3 02 c3 88 04 0e e8 90 01 04 8b f8 8b 0f 8b 49 04 8b 4c 39 30 8b 49 04 89 4c 24 1c 8b 11 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}