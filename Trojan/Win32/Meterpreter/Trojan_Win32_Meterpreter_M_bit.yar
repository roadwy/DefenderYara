
rule Trojan_Win32_Meterpreter_M_bit{
	meta:
		description = "Trojan:Win32/Meterpreter.M!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 45 10 89 45 f8 03 45 14 89 45 fc 8b 75 10 8a 06 88 45 f7 8b 4d 0c 8b 75 08 8b 7d 08 8a 06 46 51 8a 4d f7 d2 c0 59 50 56 ff 45 f8 8b 75 f8 8a 06 46 8b 5d fc 39 5d f8 75 0c 8b 55 10 89 55 f8 8b 75 f8 8a 06 46 88 45 f7 5e 58 88 07 47 49 83 f9 00 75 c9 } //1
		$a_03_1 = {50 6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 6a 00 68 90 01 03 00 e8 90 01 03 00 6a 00 e8 90 01 03 00 90 00 } //1
		$a_03_2 = {6a 40 68 00 30 00 00 ff 77 50 ff 77 34 ff 75 a8 ff 15 90 01 03 00 89 45 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}