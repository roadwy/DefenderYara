
rule Trojan_BAT_Seraph_GP_MTB{
	meta:
		description = "Trojan:BAT/Seraph.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 1e 11 09 11 23 11 27 61 11 1d 19 58 61 11 32 61 d2 9c } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}