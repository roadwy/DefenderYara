
rule Trojan_BAT_RansomCrypt_RP_MTB{
	meta:
		description = "Trojan:BAT/RansomCrypt.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {28 9f 00 00 0a 28 ae 00 00 0a 2c 3d 28 0d 00 00 06 6f ?? ?? ?? ?? 7b 13 00 00 04 11 0a 9a 00 72 ?? ?? 00 70 28 9f 00 00 0a 13 04 00 72 ?? ?? 00 70 11 04 00 72 ?? ?? 00 70 11 00 28 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}