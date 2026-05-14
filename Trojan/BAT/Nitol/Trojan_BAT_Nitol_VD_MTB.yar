
rule Trojan_BAT_Nitol_VD_MTB{
	meta:
		description = "Trojan:BAT/Nitol.VD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 04 00 00 0a 0a 06 72 01 00 00 70 6f 05 00 00 0a 06 28 06 00 00 0a 72 09 00 00 70 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}