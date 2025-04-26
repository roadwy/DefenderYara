
rule Trojan_Win32_Emotetcrypt_YAB_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.YAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 74 24 04 f7 f6 8a 1c 15 b2 11 40 00 8b 54 24 18 8a 3c 0a 28 df 8b 7c 24 14 88 3c 0f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}