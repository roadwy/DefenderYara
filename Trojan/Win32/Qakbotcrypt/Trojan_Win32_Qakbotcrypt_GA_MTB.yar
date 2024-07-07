
rule Trojan_Win32_Qakbotcrypt_GA_MTB{
	meta:
		description = "Trojan:Win32/Qakbotcrypt.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {fc f3 a4 50 c7 04 90 02 06 59 ff b3 90 02 04 8f 45 90 02 02 ff 75 90 02 02 58 55 81 04 90 02 06 29 2c 90 02 02 83 65 90 02 02 00 ff 75 90 02 02 01 04 90 02 02 52 31 14 90 02 04 89 0c 90 02 04 8d 83 90 00 } //1
		$a_02_1 = {58 59 c7 45 90 02 02 00 00 00 00 ff 75 90 02 02 01 04 90 02 02 8d 83 90 02 32 31 c9 31 c1 89 8b 90 02 04 8b 4d 90 02 02 31 c0 8b 04 90 02 02 83 ec fc ff e0 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}