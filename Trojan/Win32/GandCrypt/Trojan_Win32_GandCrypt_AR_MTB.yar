
rule Trojan_Win32_GandCrypt_AR_MTB{
	meta:
		description = "Trojan:Win32/GandCrypt.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {69 c9 fd 43 03 00 89 0d 90 01 03 00 81 05 90 01 03 00 c3 9e 26 00 81 3d 90 01 03 00 cf 12 00 00 0f b7 1d 90 01 03 00 75 90 01 01 6a 00 6a 00 ff 15 90 01 04 8b 45 f8 30 1c 06 90 0a 45 00 ff 15 90 01 04 8b 0d 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}