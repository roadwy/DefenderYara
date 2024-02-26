
rule Trojan_Win32_Meterpreter_RPX_MTB{
	meta:
		description = "Trojan:Win32/Meterpreter.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 f9 89 de 8a 06 30 07 47 66 81 3f 90 01 02 74 08 46 80 3e 90 01 01 75 ee eb ea 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_RPX_MTB_2{
	meta:
		description = "Trojan:Win32/Meterpreter.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b c7 8a 9c 3c d8 01 00 00 99 f7 fe 0f b6 cb 0f be 84 14 c4 01 00 00 03 44 24 0c 03 c8 0f b6 c9 89 4c 24 0c 8a 84 0c d8 01 00 00 88 84 3c d8 01 00 00 47 88 9c 0c d8 01 00 00 81 ff 00 01 00 00 7c be } //01 00 
		$a_01_1 = {34 39 2e 32 33 32 2e 31 39 32 2e 39 38 } //01 00  49.232.192.98
		$a_01_2 = {67 75 6f 67 75 6f } //01 00  guoguo
		$a_01_3 = {52 65 76 65 72 73 65 5f 54 43 50 5f 52 43 34 } //01 00  Reverse_TCP_RC4
		$a_01_4 = {76 69 70 65 72 2e 70 64 62 } //00 00  viper.pdb
	condition:
		any of ($a_*)
 
}