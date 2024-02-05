
rule Trojan_Win64_Meterpreter_J_attk{
	meta:
		description = "Trojan:Win64/Meterpreter.J!attk,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 03 00 "
		
	strings :
		$a_03_0 = {55 48 89 e5 48 83 ec 30 48 89 4d 10 48 8b 4d 10 e8 90 01 04 89 45 fc c7 45 f8 00 00 00 00 8b 45 fc 48 98 48 8d 55 f8 49 89 d1 41 b8 40 00 00 00 48 89 c2 48 8b 4d 10 48 8b 05 90 01 04 ff d0 48 8b 45 10 ff d0 90 90 48 83 c4 30 5d c3 90 00 } //01 00 
		$a_01_1 = {00 25 63 25 63 00 } //01 00 
		$a_01_2 = {6c 69 62 67 63 6a 2d 31 36 2e 64 6c 6c 00 5f 4a 76 5f 52 65 67 69 73 74 65 72 43 6c 61 73 73 65 73 } //01 00 
		$a_01_3 = {00 65 78 65 63 5f 73 68 65 6c 6c 63 6f 64 65 36 34 00 } //00 00 
	condition:
		any of ($a_*)
 
}