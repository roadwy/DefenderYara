
rule Trojan_BAT_AurusCrypt_A_MTB{
	meta:
		description = "Trojan:BAT/AurusCrypt.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 09 08 5d 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 61 d2 9c 09 17 58 0d 09 07 8e 69 3f 90 00 } //2
		$a_01_1 = {47 65 74 44 6f 6d 61 69 6e } //1 GetDomain
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}