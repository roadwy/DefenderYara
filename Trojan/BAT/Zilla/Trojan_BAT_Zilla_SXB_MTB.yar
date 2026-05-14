
rule Trojan_BAT_Zilla_SXB_MTB{
	meta:
		description = "Trojan:BAT/Zilla.SXB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {14 13 0b de 78 28 ?? 00 00 0a 06 6f ?? 00 00 0a 13 06 11 05 8e 69 8d 0d 00 00 01 13 07 16 13 08 2b 1e 00 11 07 11 08 11 05 11 08 91 11 06 11 08 11 06 8e 69 5d 91 61 d2 9c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}