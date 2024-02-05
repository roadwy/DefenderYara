
rule Trojan_Win32_NSISInject_RF_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 40 68 00 30 00 00 57 6a 00 ff 90 02 05 56 6a 01 90 02 20 b8 ab aa aa aa f7 e6 90 02 03 c1 ea 03 90 02 03 8d 0c 52 c1 e1 02 2b c1 90 02 02 8a 80 90 01 04 30 90 01 01 33 90 02 03 3b f7 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_NSISInject_RF_MTB_2{
	meta:
		description = "Trojan:Win32/NSISInject.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 67 67 72 65 67 61 74 66 75 6e 6b 74 69 6f 6e 65 72 6e 65 5c 53 75 62 74 65 78 74 2e 49 6e 74 } //01 00 
		$a_01_1 = {4d 75 6c 74 69 6c 61 6d 69 6e 61 74 65 64 5c 57 61 72 6c 6f 63 6b 72 79 2e 69 6e 69 } //01 00 
		$a_01_2 = {50 69 74 66 61 6c 6c 73 5c 4e 69 6b 6b 65 64 65 2e 69 6e 69 } //01 00 
		$a_01_3 = {42 65 76 69 64 73 74 68 65 64 65 72 73 5c 55 6e 72 65 64 5c 54 68 69 65 6c 6f 2e 6c 6e 6b } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_NSISInject_RF_MTB_3{
	meta:
		description = "Trojan:Win32/NSISInject.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 00 6f 00 64 00 61 00 76 00 61 00 6e 00 64 00 73 00 66 00 6c 00 61 00 73 00 6b 00 65 00 72 00 73 00 5c 00 67 00 69 00 61 00 6e 00 6e 00 69 00 6e 00 61 00 5c 00 6f 00 72 00 67 00 65 00 6c 00 73 00 } //01 00 
		$a_01_1 = {53 00 75 00 73 00 65 00 6e 00 64 00 65 00 73 00 5c 00 53 00 63 00 72 00 75 00 6d 00 70 00 74 00 69 00 6f 00 6e 00 } //01 00 
		$a_01_2 = {41 00 65 00 73 00 6f 00 70 00 69 00 61 00 6e 00 5c 00 55 00 6e 00 64 00 65 00 72 00 73 00 74 00 79 00 72 00 2e 00 54 00 65 00 69 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_NSISInject_RF_MTB_4{
	meta:
		description = "Trojan:Win32/NSISInject.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {31 d2 89 0c 24 c7 44 24 04 00 00 00 80 c7 44 24 08 01 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 10 03 00 00 00 c7 44 24 14 80 00 00 00 c7 44 24 18 00 00 00 00 ff d0 83 ec 1c 89 45 90 01 01 b8 ff ff ff ff 39 45 90 02 60 c7 04 24 00 00 00 00 89 90 01 01 24 04 c7 44 24 08 00 30 00 00 c7 44 24 0c 40 00 00 00 ff 90 00 } //01 00 
		$a_02_1 = {43 00 3a 00 5c 00 78 00 61 00 6d 00 70 00 70 00 5c 00 68 00 74 00 64 00 6f 00 63 00 73 00 5c 00 90 02 25 5c 00 4c 00 6f 00 61 00 64 00 65 00 72 00 5c 00 52 00 65 00 6c 00 65 00 61 00 73 00 65 00 5c 00 4c 00 6f 00 61 00 64 00 65 00 72 00 2e 00 70 00 64 00 62 00 90 00 } //01 00 
		$a_02_2 = {43 3a 5c 78 61 6d 70 70 5c 68 74 64 6f 63 73 5c 90 02 25 5c 4c 6f 61 64 65 72 5c 52 65 6c 65 61 73 65 5c 4c 6f 61 64 65 72 2e 70 64 62 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}