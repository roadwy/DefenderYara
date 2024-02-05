
rule Trojan_Win32_Scotter_A_bit{
	meta:
		description = "Trojan:Win32/Scotter.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 40 8b f0 68 00 10 00 00 8d 46 01 50 6a 00 ff 15 90 01 03 00 56 8b f8 68 80 90 01 02 00 57 e8 90 00 } //01 00 
		$a_01_1 = {00 55 46 6c 4a 53 55 6c 4a 53 55 6c 4a 53 55 6c 4a 53 55 6c 4a 53 55 6c 4a 4e 31 46 61 61 6b 46 59 55 44 42 42 4d } //00 00 
	condition:
		any of ($a_*)
 
}