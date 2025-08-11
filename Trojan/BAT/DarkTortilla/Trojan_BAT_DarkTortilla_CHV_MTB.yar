
rule Trojan_BAT_DarkTortilla_CHV_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.CHV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 07 6f b2 04 00 0a 00 09 07 6f b3 04 00 0a 00 09 19 6f b4 04 00 0a 00 09 6f b5 04 00 0a 13 07 73 32 04 00 0a 13 04 11 04 11 07 17 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}