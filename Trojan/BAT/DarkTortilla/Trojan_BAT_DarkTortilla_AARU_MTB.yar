
rule Trojan_BAT_DarkTortilla_AARU_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.AARU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 13 06 07 75 90 01 01 00 00 1b 11 06 28 90 01 01 00 00 0a 03 28 90 01 01 00 00 06 b4 6f 90 01 01 00 00 0a 16 13 0b 2b 92 08 17 d6 0c 90 01 01 13 0b 2b 89 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}