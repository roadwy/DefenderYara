
rule Trojan_Win32_GandCrypt_GS_MTB{
	meta:
		description = "Trojan:Win32/GandCrypt.GS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {b8 f5 d0 00 00 01 45 fc 8b 45 fc 8a 04 38 8b 0d 90 01 04 88 04 39 a1 90 01 04 47 3b f8 72 c7 8d 4d f4 51 6a 40 50 ff 35 90 00 } //1
		$a_02_1 = {55 8b ec 81 ec 20 08 00 00 a1 90 01 04 33 c5 89 45 fc 56 57 33 ff 81 3d 90 01 04 12 0f 00 00 75 90 01 01 57 8d 85 e0 f7 ff ff 50 57 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}