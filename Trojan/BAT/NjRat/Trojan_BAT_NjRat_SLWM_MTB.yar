
rule Trojan_BAT_NjRat_SLWM_MTB{
	meta:
		description = "Trojan:BAT/NjRat.SLWM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 ff 05 00 06 13 0a 11 0a 28 fb 00 00 06 7d 06 00 00 04 11 0a 28 fc 00 00 06 7d 07 00 00 04 28 fd 00 00 06 13 0f 28 fe 00 00 06 13 10 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}