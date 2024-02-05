
rule Trojan_Win32_Galock_A{
	meta:
		description = "Trojan:Win32/Galock.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 03 6a 00 6a 00 6a 00 6a 00 6a ff 8b 90 01 02 90 17 08 01 01 01 01 01 01 01 01 50 51 52 53 54 55 56 57 ff 55 90 01 01 6a 32 ff 15 90 00 } //01 00 
		$a_03_1 = {8d 4c 10 18 89 4d 90 01 01 8b 55 90 01 01 8b 45 90 01 01 03 42 60 89 45 90 01 01 8b 4d 0c c1 e9 10 90 00 } //00 00 
		$a_00_2 = {87 } //10 00 
	condition:
		any of ($a_*)
 
}