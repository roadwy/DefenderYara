
rule Trojan_BAT_Injuke_AYNA_MTB{
	meta:
		description = "Trojan:BAT/Injuke.AYNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 11 08 18 5b 06 72 61 00 00 70 18 8d 1c 00 00 01 25 16 d0 30 00 00 01 28 ?? 00 00 0a a2 25 17 d0 28 00 00 01 28 ?? 00 00 0a a2 6f ?? 00 00 0a 16 8c 28 00 00 01 18 8d 16 00 00 01 25 16 02 11 08 07 6f ?? 00 00 0a a2 25 17 08 8c 28 00 00 01 a2 6f ?? 00 00 0a a5 31 00 00 01 9c 11 08 18 58 13 08 11 08 11 04 32 97 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}