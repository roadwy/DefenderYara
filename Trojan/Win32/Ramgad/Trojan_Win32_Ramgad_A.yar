
rule Trojan_Win32_Ramgad_A{
	meta:
		description = "Trojan:Win32/Ramgad.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {bb 01 00 00 00 8b 06 8a 44 18 ff 04 90 01 01 2c 90 01 01 72 06 04 9b 2c 20 73 15 8b c6 e8 90 01 04 8b 16 0f b6 54 1a ff 83 ea 20 88 54 18 ff 43 4f 75 90 00 } //01 00 
		$a_01_1 = {55 32 78 76 59 32 73 75 5a 47 78 73 } //01 00  U2xvY2suZGxs
		$a_01_2 = {52 32 56 30 54 47 6c 7a 64 44 31 4f 64 57 31 69 5a 58 4a 55 61 48 4a 6c 59 57 52 7a } //01 00  R2V0TGlzdD1OdW1iZXJUaHJlYWRz
		$a_01_3 = {54 58 6b 67 62 6d 46 74 5a 53 42 70 63 79 42 42 63 6d 31 68 5a 32 56 6b 5a 47 39 4f 4c 43 42 70 49 47 74 70 62 47 77 67 65 57 39 31 49 48 64 6c 59 6e 4e 70 64 47 55 67 4f 79 6b 3d 2e } //00 00  TXkgbmFtZSBpcyBBcm1hZ2VkZG9OLCBpIGtpbGwgeW91IHdlYnNpdGUgOyk=.
	condition:
		any of ($a_*)
 
}