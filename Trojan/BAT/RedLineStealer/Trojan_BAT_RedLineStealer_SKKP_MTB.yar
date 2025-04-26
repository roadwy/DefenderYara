
rule Trojan_BAT_RedLineStealer_SKKP_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.SKKP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {25 16 11 13 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 11 13 1e 63 20 ff 00 00 00 5f d2 9c 25 18 11 13 20 ff 00 00 00 5f d2 9c } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}