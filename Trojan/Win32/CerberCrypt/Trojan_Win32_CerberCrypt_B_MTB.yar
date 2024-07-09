
rule Trojan_Win32_CerberCrypt_B_MTB{
	meta:
		description = "Trojan:Win32/CerberCrypt.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 10 8b 45 08 03 45 ?? 0f b6 08 33 ca 8b 55 ?? 03 55 d4 88 0a e9 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}