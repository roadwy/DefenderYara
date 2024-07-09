
rule Trojan_Win32_Trickbotcrypt_RTB_MTB{
	meta:
		description = "Trojan:Win32/Trickbotcrypt.RTB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {30 9d 63 0f 8b 44 24 ?? 89 c1 81 e9 30 fd 0d 84 89 44 24 ?? 0f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}