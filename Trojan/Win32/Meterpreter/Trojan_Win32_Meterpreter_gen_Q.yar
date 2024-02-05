
rule Trojan_Win32_Meterpreter_gen_Q{
	meta:
		description = "Trojan:Win32/Meterpreter.gen!Q,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {ad ad 4e 03 06 3d 32 33 5f 32 75 ef } //01 00 
		$a_01_1 = {8b 6b 08 8b 45 3c 8b 4c 05 78 8b 4c 0d 1c 8b 5c 29 3c 03 dd 03 6c 29 24 57 } //01 00 
		$a_03_2 = {8b f4 56 68 90 01 04 57 ff d5 ad 85 c0 74 ee 90 00 } //02 00 
		$a_03_3 = {ff d3 ad 3d 90 01 04 75 dd ff e6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}