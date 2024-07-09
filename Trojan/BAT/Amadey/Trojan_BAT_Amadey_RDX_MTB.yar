
rule Trojan_BAT_Amadey_RDX_MTB{
	meta:
		description = "Trojan:BAT/Amadey.RDX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 02 11 03 11 01 11 03 91 72 ?? ?? ?? ?? 28 03 00 00 0a 59 d2 9c } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}