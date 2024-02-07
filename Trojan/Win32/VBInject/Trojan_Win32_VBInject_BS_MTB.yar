
rule Trojan_Win32_VBInject_BS_MTB{
	meta:
		description = "Trojan:Win32/VBInject.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b d8 8b 16 33 c9 8b 42 0c 8b 95 48 ff ff ff 8a 0c 10 8b 45 d8 25 ff 00 00 00 8b d7 33 c8 81 e2 ff 00 00 00 33 ca ff 15 90 01 04 8b 0e 8b 51 0c 88 04 1a 8b 45 dc 8b 5d e0 03 c7 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_VBInject_BS_MTB_2{
	meta:
		description = "Trojan:Win32/VBInject.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {c7 45 dc 01 00 00 00 c7 45 e0 01 00 00 00 83 65 e8 00 eb 90 01 01 8b 45 e8 03 45 e0 89 45 e8 8b 45 e8 3b 45 dc 7f 90 01 01 eb 90 01 01 e8 90 01 04 32 32 8b 45 08 8b 00 ff 75 08 ff 90 00 } //01 00 
		$a_00_1 = {b9 ee ff ff 00 d9 d0 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_VBInject_BS_MTB_3{
	meta:
		description = "Trojan:Win32/VBInject.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {8b 08 8b 55 dc 2b 51 14 89 55 cc 8b 45 08 8b 08 8b 55 cc 3b 51 10 73 } //01 00 
		$a_02_1 = {eb 0c ff 15 90 01 04 89 85 60 ff ff ff 8b 4d d8 ff 15 90 01 04 8b 4d 08 8b 11 8b 4a 0c 8b 95 60 ff ff ff 88 04 11 c7 45 fc 25 00 00 00 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_VBInject_BS_MTB_4{
	meta:
		description = "Trojan:Win32/VBInject.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {04 00 02 80 c7 85 90 01 04 0a 00 00 00 c7 85 90 01 04 04 00 02 80 c7 85 90 01 04 0a 00 00 00 90 00 } //01 00 
		$a_00_1 = {71 00 43 00 48 00 72 00 73 00 37 00 48 00 38 00 74 00 30 00 78 00 76 00 37 00 61 00 31 00 69 00 36 00 65 00 54 00 4c 00 52 00 4f 00 52 00 57 00 68 00 30 00 64 00 6c 00 51 00 61 00 72 00 54 00 33 00 30 00 } //01 00  qCHrs7H8t0xv7a1i6eTLRORWh0dlQarT30
		$a_00_2 = {48 00 62 00 30 00 70 00 71 00 56 00 6c 00 59 00 68 00 5a 00 74 00 4e 00 72 00 55 00 44 00 4a 00 7a 00 4f 00 6a 00 56 00 48 00 47 00 66 00 38 00 31 00 } //01 00  Hb0pqVlYhZtNrUDJzOjVHGf81
		$a_00_3 = {75 00 59 00 6b 00 49 00 6d 00 70 00 30 00 56 00 67 00 73 00 56 00 6f 00 77 00 55 00 39 00 37 00 67 00 63 00 31 00 78 00 65 00 53 00 72 00 61 00 55 00 6e 00 46 00 79 00 4c 00 36 00 34 00 } //00 00  uYkImp0VgsVowU97gc1xeSraUnFyL64
	condition:
		any of ($a_*)
 
}