
rule Trojan_Win32_Insebro_A{
	meta:
		description = "Trojan:Win32/Insebro.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 24 01 01 00 68 90 01 02 00 10 8b 44 24 34 68 90 01 02 00 10 50 ff 15 90 01 02 00 10 83 f8 06 0f 84 6d 01 00 00 8b 4e 08 6a 00 68 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}