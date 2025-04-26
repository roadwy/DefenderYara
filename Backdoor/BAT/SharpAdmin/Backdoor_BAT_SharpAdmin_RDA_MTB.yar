
rule Backdoor_BAT_SharpAdmin_RDA_MTB{
	meta:
		description = "Backdoor:BAT/SharpAdmin.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {17 8d 10 00 00 01 25 16 11 06 a2 6f 14 00 00 0a 26 11 05 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}