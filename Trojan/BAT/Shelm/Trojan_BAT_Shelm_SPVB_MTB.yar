
rule Trojan_BAT_Shelm_SPVB_MTB{
	meta:
		description = "Trojan:BAT/Shelm.SPVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {61 d2 9c 11 0d 17 58 13 0d 11 0d 11 0c 8e 69 32 e4 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}