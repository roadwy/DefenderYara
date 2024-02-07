
rule Worm_Win32_Phorpiex_S{
	meta:
		description = "Worm:Win32/Phorpiex.S,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {75 4e 6a 00 6a 00 6a 00 6a 11 e8 90 01 04 6a 00 6a 00 6a 00 6a 56 e8 90 01 04 6a 00 6a 02 6a 00 6a 56 e8 90 01 04 6a 00 6a 02 6a 00 6a 11 e8 90 01 04 6a 00 6a 00 6a 00 6a 0d 90 00 } //01 00 
		$a_01_1 = {54 43 68 61 74 52 69 63 68 45 64 69 74 00 } //01 00  䍔慨剴捩䕨楤t
		$a_01_2 = {69 6d 61 67 65 73 2e 70 68 70 3f } //00 00  images.php?
	condition:
		any of ($a_*)
 
}