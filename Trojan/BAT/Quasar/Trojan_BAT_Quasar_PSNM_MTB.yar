
rule Trojan_BAT_Quasar_PSNM_MTB{
	meta:
		description = "Trojan:BAT/Quasar.PSNM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 33 00 00 0a 7e 01 00 00 04 02 08 6f 34 00 00 0a 28 35 00 00 0a a5 01 00 00 1b 0b 11 07 20 85 9c 7f 3d 5a 20 4d f2 1c 75 61 38 51 fd ff ff } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}