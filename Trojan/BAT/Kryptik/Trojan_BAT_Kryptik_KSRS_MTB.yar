
rule Trojan_BAT_Kryptik_KSRS_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.KSRS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {25 26 0a 20 83 00 00 00 28 ?? ?? ?? 06 25 26 28 ?? ?? ?? 06 25 26 0b 06 20 c4 00 00 00 28 ?? ?? ?? 06 25 26 20 05 01 00 00 28 ?? ?? ?? 06 25 26 28 ?? ?? ?? 06 25 26 0a 07 20 c4 00 00 00 28 ?? ?? ?? 06 25 26 20 05 01 00 00 28 ?? ?? ?? 06 25 26 28 ?? ?? ?? 06 25 26 0b 06 28 ?? ?? ?? 0a 25 26 0c 08 20 26 01 00 00 28 ?? ?? ?? 06 25 26 6f ?? ?? ?? 0a 25 26 0d 09 20 47 01 00 00 28 ?? ?? ?? 06 25 26 6f ?? ?? ?? 0a 25 26 13 04 11 04 14 1a 28 ?? ?? ?? 06 25 26 13 07 11 07 16 28 ?? ?? ?? 0a 25 26 6f ?? ?? ?? 0a 25 26 a2 11 07 17 72 5b 00 00 70 a2 11 07 18 07 a2 11 07 19 16 8c 06 00 00 01 a2 11 07 6f ?? ?? ?? 0a 25 26 26 28 ?? ?? ?? 06 28 ?? ?? ?? 06 17 13 06 de 15 13 05 11 05 6f ?? ?? ?? 0a 25 26 28 ?? ?? ?? 0a 16 13 06 de 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}