
rule Trojan_Win32_Meterpreter_A{
	meta:
		description = "Trojan:Win32/Meterpreter.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {d9 74 24 f4 90 02 10 31 90 01 02 83 90 01 02 03 90 01 02 e2 f5 90 00 } //01 00 
		$a_01_1 = {68 99 a5 74 61 ff d5 85 c0 74 0a ff 4e 08 75 ec } //01 00 
		$a_03_2 = {5d 68 74 74 70 00 68 77 69 6e 68 54 68 90 01 04 ff d5 31 db 53 53 53 53 53 68 90 01 04 ff d5 53 68 52 11 00 00 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}