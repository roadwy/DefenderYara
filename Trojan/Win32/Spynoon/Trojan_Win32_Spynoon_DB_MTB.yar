
rule Trojan_Win32_Spynoon_DB_MTB{
	meta:
		description = "Trojan:Win32/Spynoon.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {8a 04 0f f6 d0 32 c1 02 c1 f6 d0 02 c1 f6 d0 02 c1 d0 c8 02 c1 f6 d8 32 c1 f6 d0 2c 90 01 01 88 04 0f 41 3b 4d fc 72 da 90 00 } //02 00 
		$a_03_1 = {8a 04 0f b2 90 01 01 04 90 01 01 d0 c0 34 90 01 01 2a d0 32 d1 2a d1 c0 ca 90 01 01 f6 d2 c0 ca 90 01 01 80 f2 90 01 01 80 ea 90 01 01 80 f2 90 01 01 f6 da c0 c2 90 01 01 80 c2 90 01 01 88 14 0f 41 3b 4d fc 72 cd 90 00 } //05 00 
		$a_01_2 = {47 46 48 46 47 48 54 52 59 52 45 } //00 00 
	condition:
		any of ($a_*)
 
}