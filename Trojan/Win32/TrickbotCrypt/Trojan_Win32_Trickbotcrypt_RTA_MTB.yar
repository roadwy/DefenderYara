
rule Trojan_Win32_Trickbotcrypt_RTA_MTB{
	meta:
		description = "Trojan:Win32/Trickbotcrypt.RTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {e8 6b 5d 60 89 4d 90 01 01 8b 45 90 01 01 89 c1 81 e9 98 f0 68 a4 89 45 90 01 01 0f 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}