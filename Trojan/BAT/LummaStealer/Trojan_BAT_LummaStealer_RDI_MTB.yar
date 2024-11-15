
rule Trojan_BAT_LummaStealer_RDI_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.RDI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 06 07 6f 22 00 00 0a 0d 73 23 00 00 0a 13 04 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}