
rule Trojan_Win32_Emotetcrypt_YAA_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 04 35 ?? ?? ?? ?? c7 44 24 44 00 00 00 00 c7 44 24 40 00 00 00 00 8b 4c 24 10 8a 3c 11 28 df 8b 54 24 1c 88 7c 24 23 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}