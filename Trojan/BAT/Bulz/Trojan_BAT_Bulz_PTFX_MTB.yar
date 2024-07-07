
rule Trojan_BAT_Bulz_PTFX_MTB{
	meta:
		description = "Trojan:BAT/Bulz.PTFX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {2c 07 02 03 28 90 01 01 00 00 0a 73 1a 00 00 0a 25 02 6f 1b 00 00 0a 25 17 6f 1c 00 00 0a 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}