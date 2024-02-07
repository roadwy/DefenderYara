
rule Ransom_Win32_Wannaren_A{
	meta:
		description = "Ransom:Win32/Wannaren.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {2e 57 61 6e 6e 61 52 65 6e } //01 00  .WannaRen
		$a_01_1 = {43 72 79 70 74 47 65 74 4b 65 79 50 61 72 61 6d 00 44 65 6c 65 74 65 46 69 6c 65 41 00 50 61 74 68 46 69 6e 64 46 69 6c 65 } //01 00 
		$a_03_2 = {41 ff ff ff 81 90 01 01 3f ff ff ff c1 90 01 01 0a 81 90 01 01 ff 01 00 00 81 90 01 01 ff 01 00 00 81 90 01 01 ff 7f 00 00 90 00 } //01 00 
		$a_03_3 = {75 50 80 7c 90 01 02 64 75 49 80 7c 90 01 02 6f 75 42 80 7c 90 01 02 62 75 3b 80 7c 90 01 02 65 75 90 00 } //00 00 
		$a_00_4 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}