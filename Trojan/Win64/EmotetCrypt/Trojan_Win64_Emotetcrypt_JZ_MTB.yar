
rule Trojan_Win64_Emotetcrypt_JZ_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.JZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f af c2 48 98 4c 89 ca 48 29 c2 48 8b 45 28 48 01 d0 0f b6 00 44 31 c0 88 01 83 45 fc 01 8b 45 fc 48 98 8b 15 90 01 04 48 63 ca 48 8b 55 20 48 01 d1 8b 15 90 01 04 48 63 d2 48 29 d1 8b 15 90 01 04 48 63 d2 48 29 d1 8b 15 90 01 04 48 63 d2 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}