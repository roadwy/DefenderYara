
rule Trojan_BAT_Bulz_PTBX_MTB{
	meta:
		description = "Trojan:BAT/Bulz.PTBX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 11 00 00 0a 02 50 6f 12 00 00 0a 2a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}