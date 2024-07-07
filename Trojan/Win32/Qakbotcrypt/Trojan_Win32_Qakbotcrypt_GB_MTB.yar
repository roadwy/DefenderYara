
rule Trojan_Win32_Qakbotcrypt_GB_MTB{
	meta:
		description = "Trojan:Win32/Qakbotcrypt.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {03 c6 03 45 90 02 02 8b 0d 90 02 04 03 4d 90 02 02 03 4d 90 02 02 03 4d 90 02 02 8b 15 90 02 04 8b 35 90 02 04 8a 04 90 02 02 88 04 90 02 02 8b 0d 90 02 04 83 c1 01 89 0d 90 02 04 eb 90 00 } //1
		$a_02_1 = {8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 31 0d 90 02 04 c7 05 90 02 04 00 00 00 00 8b 1d 90 02 04 01 1d 90 02 04 a1 90 02 04 8b 0d 90 02 04 89 08 5b 5d c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}