
rule Trojan_BAT_Ursu_AMBA_MTB{
	meta:
		description = "Trojan:BAT/Ursu.AMBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 02 50 28 ?? 00 00 06 02 50 8e 69 28 ?? 00 00 06 2a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}