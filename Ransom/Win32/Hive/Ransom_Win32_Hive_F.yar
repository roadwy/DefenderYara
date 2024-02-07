
rule Ransom_Win32_Hive_F{
	meta:
		description = "Ransom:Win32/Hive.F,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 6b 65 79 } //01 00  .key
		$a_02_1 = {65 78 70 61 6e 64 20 33 32 2d 62 79 74 65 20 6b 65 78 90 01 01 61 6e 64 20 33 32 2d 62 79 74 65 20 6b 90 00 } //01 00 
		$a_03_2 = {65 78 65 4e 55 4c 63 6f 75 6c 64 6e 27 74 20 67 65 6e 65 72 61 74 65 20 72 61 6e 64 6f 6d 20 62 90 01 01 74 65 73 3a 20 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}