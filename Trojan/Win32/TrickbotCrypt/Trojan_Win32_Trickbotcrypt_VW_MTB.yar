
rule Trojan_Win32_Trickbotcrypt_VW_MTB{
	meta:
		description = "Trojan:Win32/Trickbotcrypt.VW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 4c 24 90 01 01 8b 90 02 05 8a 90 01 02 8b 90 02 08 30 14 90 02 06 3b 90 02 05 0f 8c 90 02 04 8a 90 01 03 8b 90 01 03 8a 90 01 06 88 90 02 0a c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}