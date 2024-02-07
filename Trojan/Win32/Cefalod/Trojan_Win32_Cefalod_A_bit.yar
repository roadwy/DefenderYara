
rule Trojan_Win32_Cefalod_A_bit{
	meta:
		description = "Trojan:Win32/Cefalod.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,20 00 20 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {2e 76 6d 70 32 00 00 00 } //0a 00 
		$a_01_1 = {61 64 6f 70 6c 61 79 2e 78 63 6d 2e 69 63 61 66 65 38 2e 6e 65 74 } //0a 00  adoplay.xcm.icafe8.net
		$a_01_2 = {51 00 51 00 5f 00 54 00 53 00 45 00 48 00 5f 00 46 00 4c 00 41 00 47 00 5f 00 25 00 64 00 } //01 00  QQ_TSEH_FLAG_%d
		$a_01_3 = {00 71 71 2e 65 78 65 00 } //01 00 
		$a_01_4 = {44 52 52 00 5c 5c 2e 5c 70 69 70 65 5c 53 57 4e 54 72 61 63 65 } //00 00 
		$a_00_5 = {5d 04 00 00 fc 74 03 80 5c 22 00 00 01 75 03 80 00 00 01 00 08 00 0c 00 ac 21 42 61 6e 6b } //65 72 
	condition:
		any of ($a_*)
 
}