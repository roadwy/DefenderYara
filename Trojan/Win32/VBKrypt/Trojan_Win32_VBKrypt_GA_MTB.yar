
rule Trojan_Win32_VBKrypt_GA_MTB{
	meta:
		description = "Trojan:Win32/VBKrypt.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b c8 8b c3 03 ca 99 f7 f9 8d 45 ?? 50 8b da ff 15 [0-04] 8b 8d [0-04] 8a 14 08 32 da 8d 55 ?? 52 ff 15 [0-04] 8b 8d [0-04] 8d 55 ?? 52 88 1c 08 8d 45 ?? 50 6a ?? ff 15 [0-04] 8b 4d ?? b8 [0-04] 83 c4 ?? 03 c8 89 4d } //1
		$a_00_1 = {42 00 4d 00 47 00 44 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 65 00 72 00 } //1 BMGDocumenter
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}