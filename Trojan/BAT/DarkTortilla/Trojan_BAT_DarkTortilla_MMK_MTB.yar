
rule Trojan_BAT_DarkTortilla_MMK_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.MMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 0a 2b 89 09 75 aa 00 00 01 19 6f 90 01 03 0a 09 75 aa 00 00 01 07 75 09 00 00 1b 6f 48 01 00 0a 18 13 0a 38 64 ff ff ff 09 75 aa 00 00 01 07 74 09 00 00 1b 6f 49 01 00 0a 09 75 aa 00 00 01 09 74 aa 00 00 01 6f 4a 01 00 0a 09 75 aa 00 00 01 6f 90 01 03 0a 6f 90 01 03 0a 13 05 1a 13 0a 38 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}