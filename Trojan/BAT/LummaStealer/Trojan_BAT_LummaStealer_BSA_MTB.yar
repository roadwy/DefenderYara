
rule Trojan_BAT_LummaStealer_BSA_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.BSA!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 08 11 11 91 d6 0d 11 11 17 d6 13 11 11 11 11 10 31 ed } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}