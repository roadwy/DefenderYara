
rule PWS_Win32_Chyup_A{
	meta:
		description = "PWS:Win32/Chyup.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {66 66 5f 62 2e 69 64 20 3d 20 22 59 75 50 69 35 35 22 3b } //02 00  ff_b.id = "YuPi55";
		$a_03_1 = {3f 67 65 74 3d 90 17 03 06 04 04 69 66 72 61 6d 65 74 61 73 6b 6c 69 6e 6b 90 00 } //01 00 
		$a_01_2 = {3f 73 65 6e 64 3d 00 } //01 00 
		$a_01_3 = {32 31 00 00 ff ff ff ff 01 00 00 00 3a 00 } //00 00 
	condition:
		any of ($a_*)
 
}