
rule Trojan_BAT_Zilla_GPN_MTB{
	meta:
		description = "Trojan:BAT/Zilla.GPN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {61 13 04 1d 13 05 00 11 05 19 fe 01 2c 0c 02 6f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}