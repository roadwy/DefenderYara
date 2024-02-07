
rule Trojan_Win32_VBKrypt_GA_MTB{
	meta:
		description = "Trojan:Win32/VBKrypt.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b c8 8b c3 03 ca 99 f7 f9 8d 45 90 01 01 50 8b da ff 15 90 02 04 8b 8d 90 02 04 8a 14 08 32 da 8d 55 90 01 01 52 ff 15 90 02 04 8b 8d 90 02 04 8d 55 90 01 01 52 88 1c 08 8d 45 90 01 01 50 6a 90 01 01 ff 15 90 02 04 8b 4d 90 01 01 b8 90 02 04 83 c4 90 01 01 03 c8 89 4d 90 00 } //01 00 
		$a_00_1 = {42 00 4d 00 47 00 44 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 65 00 72 00 } //00 00  BMGDocumenter
	condition:
		any of ($a_*)
 
}