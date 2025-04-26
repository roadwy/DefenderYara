
rule Trojan_BAT_ScnabrCrypt_A_MTB{
	meta:
		description = "Trojan:BAT/ScnabrCrypt.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 00 0a 72 03 00 00 70 7e ?? 00 00 0a 6f ?? 00 00 0a 28 90 09 0a 00 00 00 0a ?? 16 ?? 8e 69 6f } //2
		$a_03_1 = {03 8e 69 8d ?? 00 00 01 13 04 09 11 04 16 11 04 8e 69 6f } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}