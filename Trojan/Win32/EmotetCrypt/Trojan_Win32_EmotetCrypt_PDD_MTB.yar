
rule Trojan_Win32_EmotetCrypt_PDD_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.PDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {b8 25 49 92 24 f7 e6 8b c6 2b c2 d1 e8 03 c2 c1 e8 04 8d 0c c5 00 00 00 00 2b c8 03 c9 03 c9 8b d6 2b d1 8a 04 2a 30 04 3e } //01 00 
		$a_81_1 = {4c 63 6f 4b 62 74 4e 45 79 4a 59 65 43 52 32 57 43 71 5a 75 48 78 67 70 } //00 00 
	condition:
		any of ($a_*)
 
}