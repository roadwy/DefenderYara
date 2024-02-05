
rule Trojan_Win32_Inhoo_A{
	meta:
		description = "Trojan:Win32/Inhoo.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {74 3e 8d 45 fc 8b 35 90 01 01 10 00 10 50 6a 40 6a 40 c7 45 e8 90 01 02 00 10 ff 75 08 c7 45 ec 90 01 02 00 10 53 ff d6 85 c0 74 2b 90 00 } //01 00 
		$a_02_1 = {6a 00 ff 35 90 01 02 00 10 68 90 01 02 00 10 6a 07 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}