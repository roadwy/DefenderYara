
rule Worm_Win32_Vobfus_gen_U{
	meta:
		description = "Worm:Win32/Vobfus.gen!U,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {00 0f 80 10 00 6c 78 ff e4 f4 ff fe 5d 20 02 } //01 00 
		$a_00_1 = {00 10 6c 78 ff e4 04 74 ff f5 00 00 00 00 fc 77 } //01 00 
		$a_02_2 = {40 f5 01 00 00 00 fc 78 90 09 16 00 00 1e 6b 90 01 02 94 08 00 90 01 01 00 6c 90 01 02 aa 6c 90 01 02 94 08 00 90 00 } //01 00 
		$a_02_3 = {f5 00 00 00 00 f5 ff ff ff ff 04 90 01 02 fe 8e 00 00 00 00 10 00 80 08 04 90 01 02 94 08 00 90 01 02 94 08 00 90 01 02 5e 90 01 04 71 90 01 02 04 90 01 02 5a 6c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}