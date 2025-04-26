
rule Trojan_BAT_Dcstl_PTCM_MTB{
	meta:
		description = "Trojan:BAT/Dcstl.PTCM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 2c 07 09 6f 46 00 00 0a 00 dc 28 ?? 00 00 0a 08 6f 5f 00 00 0a 6f 60 00 00 0a 13 04 de 16 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}