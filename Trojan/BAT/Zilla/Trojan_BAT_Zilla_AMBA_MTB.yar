
rule Trojan_BAT_Zilla_AMBA_MTB{
	meta:
		description = "Trojan:BAT/Zilla.AMBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 06 1e 8d 90 01 01 00 00 01 25 16 7e 90 01 01 00 00 0a 6f 90 01 01 00 00 0a a2 25 17 72 90 01 01 00 00 70 a2 25 18 7e 90 01 01 00 00 0a 6f 90 01 01 00 00 0a a2 25 19 72 90 01 01 00 00 70 a2 25 1a 7e 90 01 01 00 00 0a 6f 90 01 01 00 00 0a a2 25 1b 72 90 01 01 00 00 70 a2 25 1c 7e 90 01 01 00 00 0a 6f 90 01 01 00 00 0a a2 25 1d 72 90 01 01 00 00 70 a2 28 90 01 01 00 00 0a 18 17 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}