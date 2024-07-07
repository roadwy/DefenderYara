
rule Trojan_Win32_Trickbotcrypt_VI_MTB{
	meta:
		description = "Trojan:Win32/Trickbotcrypt.VI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 4c 24 90 02 01 8b d5 2b 15 90 02 04 45 03 c2 8b 15 90 02 04 8a 0c 90 02 01 90 17 04 01 01 01 01 31 32 30 33 90 01 01 3b 6c 90 02 02 0f 8c 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}