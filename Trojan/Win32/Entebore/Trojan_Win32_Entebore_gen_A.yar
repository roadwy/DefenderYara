
rule Trojan_Win32_Entebore_gen_A{
	meta:
		description = "Trojan:Win32/Entebore.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 52 45 51 4b 45 59 25 } //01 00 
		$a_01_1 = {22 6a 73 22 3a 20 5b 20 22 25 43 53 46 49 4c 45 25 22 20 5d 2c 20 0a } //01 00 
		$a_03_2 = {07 00 00 00 67 6f 6f 67 6c 65 2e 00 90 02 08 06 00 00 00 79 61 68 6f 6f 2e 00 90 02 08 05 00 00 00 62 69 6e 67 2e 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}