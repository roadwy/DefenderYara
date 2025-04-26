
rule Trojan_BAT_Chopper_PTGX_MTB{
	meta:
		description = "Trojan:BAT/Chopper.PTGX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {d0 03 00 00 02 72 b7 03 00 70 72 e1 03 00 70 16 8d 0f 00 00 01 1a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}