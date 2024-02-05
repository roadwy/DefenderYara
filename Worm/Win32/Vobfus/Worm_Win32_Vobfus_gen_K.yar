
rule Worm_Win32_Vobfus_gen_K{
	meta:
		description = "Worm:Win32/Vobfus.gen!K,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {4a f5 02 00 00 00 b2 aa f5 02 00 00 00 aa 6c 90 01 01 ff 0b 90 01 01 00 0c 00 31 90 01 01 ff 90 00 } //01 00 
		$a_03_1 = {f4 02 eb 6b 74 ff eb fb cf e8 c4 fd 69 90 01 02 fc 46 71 90 01 02 00 0e 6c 90 01 02 f5 00 00 00 00 cc 1c 90 00 } //01 00 
		$a_03_2 = {f4 58 fc 0d 90 02 0a f4 5b fc 0d 90 08 01 80 f4 50 fc 0d 90 08 02 30 f3 c3 00 fc 0d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}