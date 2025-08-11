
rule Trojan_BAT_DarkTortilla_AB_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 13 0b 00 73 47 01 00 0a 13 16 00 11 16 17 73 48 01 00 0a 13 18 11 18 11 0b 16 11 0b 8e 69 6f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}