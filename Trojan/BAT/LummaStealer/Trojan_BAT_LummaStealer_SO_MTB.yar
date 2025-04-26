
rule Trojan_BAT_LummaStealer_SO_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.SO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 72 61 00 00 70 6f 1e 00 00 0a 80 02 00 00 04 dd 0d 00 00 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}