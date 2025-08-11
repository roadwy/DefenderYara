
rule Trojan_BAT_Stealerium_SPP_MTB{
	meta:
		description = "Trojan:BAT/Stealerium.SPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 02 11 03 11 00 11 03 91 11 04 11 03 11 04 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}