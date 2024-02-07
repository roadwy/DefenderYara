
rule Worm_Win32_Neeris_gen_D{
	meta:
		description = "Worm:Win32/Neeris.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {85 db 75 2a 83 f8 20 74 05 83 f8 05 75 20 6a 01 5b 68 98 3a 00 00 ff 15 } //02 00 
		$a_03_1 = {8d 3c 10 0f b6 01 0f b6 cb 03 c1 8b ce 99 f7 f9 8b 4d 08 8a 84 15 90 01 04 32 04 39 ff 45 fc 88 07 90 00 } //01 00 
		$a_03_2 = {6a 68 ff 15 90 01 04 6a 04 8d 75 90 01 01 99 59 f7 f9 85 c0 7e 90 01 01 53 57 8b 3d 90 01 04 8b d8 56 ff 15 90 01 04 83 f8 02 75 90 00 } //01 00 
		$a_01_3 = {00 73 79 73 64 72 76 33 32 2e 73 79 73 00 } //01 00  猀獹牤㍶⸲祳s
		$a_01_4 = {43 61 63 68 65 2d 43 6f 6e 74 72 6f 6c 3a 20 6e 6f 2d 63 61 63 68 65 2c 6e 6f 2d 73 74 6f 72 65 2c 6d 61 78 2d 61 67 65 3d 30 } //00 00  Cache-Control: no-cache,no-store,max-age=0
	condition:
		any of ($a_*)
 
}