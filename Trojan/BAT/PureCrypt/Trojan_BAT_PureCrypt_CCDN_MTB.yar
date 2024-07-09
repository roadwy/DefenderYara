
rule Trojan_BAT_PureCrypt_CCDN_MTB{
	meta:
		description = "Trojan:BAT/PureCrypt.CCDN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 11 05 16 6f ?? ?? ?? ?? 13 06 12 06 28 ?? ?? ?? ?? 13 07 11 04 11 07 6f ?? ?? ?? ?? 11 05 17 58 13 05 11 05 09 6f ?? ?? ?? ?? 32 d3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}