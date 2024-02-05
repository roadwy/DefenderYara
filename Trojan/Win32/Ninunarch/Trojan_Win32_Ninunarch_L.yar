
rule Trojan_Win32_Ninunarch_L{
	meta:
		description = "Trojan:Win32/Ninunarch.L,SIGNATURE_TYPE_PEHSTR,6f 00 6f 00 04 00 00 64 00 "
		
	strings :
		$a_01_0 = {4b c4 52 ff 46 b8 4c ff 05 0e 05 59 ff ff ff 01 00 01 00 17 52 70 53 cf ac e4 af ff b4 e6 b7 ff bd e9 bf ff c8 } //0a 00 
		$a_01_1 = {64 31 6f 32 6f 33 68 34 6b 35 74 36 74 37 6d 38 63 39 75 30 70 31 6b 32 69 33 75 34 74 } //01 00 
		$a_01_2 = {6c 61 62 65 6c 52 65 74 72 79 53 65 6e 64 53 4d 53 } //01 00 
		$a_01_3 = {51 46 74 70 44 54 50 } //00 00 
	condition:
		any of ($a_*)
 
}