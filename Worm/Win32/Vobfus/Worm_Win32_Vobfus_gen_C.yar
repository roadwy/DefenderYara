
rule Worm_Win32_Vobfus_gen_C{
	meta:
		description = "Worm:Win32/Vobfus.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {4a f5 02 00 00 00 b2 aa f5 02 00 00 00 aa 6c 90 01 01 ff 0b 90 01 01 00 0c 00 31 90 01 01 ff 90 00 } //01 00 
		$a_03_1 = {f3 00 01 c1 e7 04 90 01 01 ff 9d fb 12 fc 0d 90 00 } //01 00 
		$a_03_2 = {fb 12 fc 0d 6c 90 01 02 80 90 01 02 fc a0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}