
rule Backdoor_Win32_Mokspolx_A{
	meta:
		description = "Backdoor:Win32/Mokspolx.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {99 be 7f 00 00 00 f7 fe 90 09 03 00 83 f0 90 00 } //01 00 
		$a_03_1 = {2b d6 52 8d 84 35 90 01 02 fe ff 50 53 ff d7 03 f0 90 09 05 00 90 03 01 01 b8 ba 00 c8 00 00 90 00 } //01 00 
		$a_03_2 = {83 ff 10 7d 29 0f b6 90 01 01 1f 51 68 90 01 04 ba 21 00 00 00 90 00 } //01 00 
		$a_01_3 = {c7 84 24 9c 00 00 00 58 5a 4b 00 33 c9 8d 70 01 } //00 00 
	condition:
		any of ($a_*)
 
}