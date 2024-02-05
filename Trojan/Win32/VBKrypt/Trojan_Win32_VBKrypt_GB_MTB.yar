
rule Trojan_Win32_VBKrypt_GB_MTB{
	meta:
		description = "Trojan:Win32/VBKrypt.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b c8 8b c3 03 ca 99 90 02 06 f7 f9 8d 45 90 01 01 50 8b da ff 15 90 02 04 8b 95 90 02 04 33 c9 8a 0c 10 33 cb ff 15 90 02 04 8a d8 8d 45 90 01 01 50 ff 15 90 02 04 8b 8d 90 02 04 8d 55 90 01 01 52 88 1c 08 8d 45 90 01 01 50 6a 02 ff 15 90 02 04 b8 90 02 04 83 c4 90 01 01 66 03 45 ec 90 00 } //01 00 
		$a_02_1 = {8b c8 8b c3 03 ca 99 f7 f9 8d 45 90 01 01 50 8b da ff 15 90 02 04 8b 90 02 08 32 90 01 01 8d 90 02 03 ff 15 90 02 04 8b 8d 90 02 04 8d 55 90 01 01 52 88 1c 08 8d 45 90 01 01 50 6a 02 ff 15 90 02 07 b8 90 02 04 83 c4 0c 90 0a 96 00 33 db 8a 1c 0a 8d 55 b4 52 ff d7 0f bf 55 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}