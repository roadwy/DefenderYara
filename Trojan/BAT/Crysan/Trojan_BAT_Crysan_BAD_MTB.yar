
rule Trojan_BAT_Crysan_BAD_MTB{
	meta:
		description = "Trojan:BAT/Crysan.BAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 05 11 05 2d 0c 02 72 97 00 00 70 28 0b 00 00 0a 0d 09 28 24 00 00 0a 16 fe 01 13 05 11 05 2d 5d 00 73 25 00 00 0a 13 04 11 04 72 ad 00 00 70 ?? ?? 00 00 0a 00 11 04 72 bd 00 00 70 09 72 c7 00 00 70 28 10 00 00 0a ?? ?? 00 00 0a 00 11 04 17 ?? ?? 00 00 0a 00 11 04 17 ?? ?? 00 00 0a 00 11 04 16 ?? ?? 00 00 0a 00 11 04 0b } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}