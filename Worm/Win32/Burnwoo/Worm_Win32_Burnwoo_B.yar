
rule Worm_Win32_Burnwoo_B{
	meta:
		description = "Worm:Win32/Burnwoo.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {bf 41 00 00 00 83 24 bd 90 01 04 00 47 83 ff 5a 7e f2 eb 38 e8 90 01 04 83 f8 01 75 10 90 00 } //01 00 
		$a_01_1 = {2e 25 73 2f 77 2e 70 68 70 3f 69 64 3d 25 73 } //00 00  .%s/w.php?id=%s
	condition:
		any of ($a_*)
 
}