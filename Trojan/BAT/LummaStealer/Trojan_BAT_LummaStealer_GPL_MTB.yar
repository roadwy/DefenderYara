
rule Trojan_BAT_LummaStealer_GPL_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.GPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 03 66 5f 02 66 03 5f 60 8c 29 00 00 01 0a 2b 00 06 2a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}