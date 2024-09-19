
rule Trojan_Win32_Emotetcrypt_YAC_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.YAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 f6 89 74 24 54 89 44 24 50 8b 44 24 40 8a 34 08 30 d6 c6 44 24 5f 80 8a 54 24 3b 80 e2 4a 88 54 24 5f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}