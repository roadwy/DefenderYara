
rule PWS_Win32_Fareit_BB_bit{
	meta:
		description = "PWS:Win32/Fareit.BB!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 a1 30 00 00 00 8b 40 0c 8b 40 0c 8b 00 8b 00 8b 40 18 } //01 00 
		$a_03_1 = {0f b7 ce 8a 04 01 32 04 fd 90 01 04 46 88 04 11 0f b7 04 fd 90 01 04 66 3b f0 72 db 90 09 07 00 8b 04 fd 90 00 } //01 00 
		$a_03_2 = {0f b6 04 07 33 c1 c1 e9 08 0f b6 c0 33 0c 85 90 01 04 47 8b 45 90 01 01 3b fb 72 e5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}