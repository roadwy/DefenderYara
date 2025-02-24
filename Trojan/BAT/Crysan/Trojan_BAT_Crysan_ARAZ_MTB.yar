
rule Trojan_BAT_Crysan_ARAZ_MTB{
	meta:
		description = "Trojan:BAT/Crysan.ARAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 11 06 9a 0c 08 12 03 28 ?? ?? ?? 0a 2c 17 06 09 7e ?? ?? ?? 04 61 d1 13 07 12 07 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 11 06 17 58 13 06 11 06 11 05 8e 69 32 cb } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}