
rule PWS_Win32_Kegotip_C{
	meta:
		description = "PWS:Win32/Kegotip.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 4d 53 57 51 2a 2e 74 6d 70 00 } //01 00 
		$a_01_1 = {54 75 72 62 6f 46 54 50 5c 61 64 64 72 62 6b 2e 64 61 74 00 } //01 00 
		$a_03_2 = {83 e2 10 74 90 01 01 0f be 85 90 01 02 ff ff 83 f8 2e 75 22 0f be 8d 90 01 02 ff ff 85 c9 74 90 01 01 0f be 95 90 01 02 ff ff 83 fa 2e 75 0b 0f be 85 90 01 02 ff ff 85 c0 74 90 01 01 68 04 01 00 00 8b 4d 08 51 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}