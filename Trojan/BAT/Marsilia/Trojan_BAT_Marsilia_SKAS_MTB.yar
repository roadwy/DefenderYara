
rule Trojan_BAT_Marsilia_SKAS_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.SKAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 9a 13 04 7e ?? 00 00 04 11 04 18 28 ?? 00 00 06 20 ff 00 00 00 5f 13 05 08 09 7e ?? 00 00 04 11 05 28 ?? 00 00 06 9c 00 09 17 58 0d 09 07 8e 69 fe 04 13 07 11 07 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}