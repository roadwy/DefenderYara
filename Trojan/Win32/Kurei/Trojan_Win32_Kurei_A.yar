
rule Trojan_Win32_Kurei_A{
	meta:
		description = "Trojan:Win32/Kurei.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52 00 00 05 00 00 00 04 00 08 02 00 00 00 31 f1 63 14 00 00 00 04 67 41 4d 41 00 00 b1 9e 61 4c 41 f7 } //00 00 
	condition:
		any of ($a_*)
 
}