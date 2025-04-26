
rule Trojan_Win32_VBKrypt_GB_MTB{
	meta:
		description = "Trojan:Win32/VBKrypt.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b c8 8b c3 03 ca 99 [0-06] f7 f9 8d 45 ?? 50 8b da ff 15 [0-04] 8b 95 [0-04] 33 c9 8a 0c 10 33 cb ff 15 [0-04] 8a d8 8d 45 ?? 50 ff 15 [0-04] 8b 8d [0-04] 8d 55 ?? 52 88 1c 08 8d 45 ?? 50 6a 02 ff 15 [0-04] b8 [0-04] 83 c4 ?? 66 03 45 ec } //1
		$a_02_1 = {8b c8 8b c3 03 ca 99 f7 f9 8d 45 ?? 50 8b da ff 15 [0-04] 8b [0-08] 32 ?? 8d [0-03] ff 15 [0-04] 8b 8d [0-04] 8d 55 ?? 52 88 1c 08 8d 45 ?? 50 6a 02 ff 15 [0-07] b8 [0-04] 83 c4 0c 90 0a 96 00 33 db 8a 1c 0a 8d 55 b4 52 ff d7 0f bf 55 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}