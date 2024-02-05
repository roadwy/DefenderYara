
rule Trojan_Win32_Alureon_AL_MTB{
	meta:
		description = "Trojan:Win32/Alureon.AL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 0c 14 52 b2 90 01 02 5a 8a 2f 52 b2 04 90 01 01 5a 32 e9 52 b2 04 90 01 01 5a 88 2f 52 b2 04 90 01 01 5a 47 52 b2 04 90 01 01 5a 4d 52 b2 04 90 01 01 5a 0f 85 90 00 } //01 00 
		$a_00_1 = {36 55 50 03 fe 8d 3c 38 33 c0 03 fe 8d 3c 38 68 2c ca 3a 16 03 fe 8d 3c 38 68 35 d0 15 dc 03 fe 8d 3c 38 6a 00 03 fe 8d 3c 38 68 a2 7d 80 62 6a 53 83 c4 04 54 6a 53 83 c4 04 68 30 08 01 00 6a 53 83 c4 04 6a 10 52 } //00 00 
	condition:
		any of ($a_*)
 
}