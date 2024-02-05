
rule Trojan_Win32_VBKrypt_GG_MTB{
	meta:
		description = "Trojan:Win32/VBKrypt.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b c8 8b c6 99 f7 f9 8b 45 ac 66 33 90 02 02 8b 4d 90 01 01 8b 31 8d 55 d0 52 ff 15 90 02 04 8b 4d 90 01 01 8b 11 2b 42 14 8b 4e 0c 88 1c 01 8d 4d 84 ff 15 90 02 23 89 85 90 02 04 83 bd 90 02 04 00 90 00 } //01 00 
		$a_00_1 = {5c 00 44 00 61 00 72 00 69 00 6e 00 73 00 2e 00 76 00 62 00 70 00 } //00 00 
	condition:
		any of ($a_*)
 
}