
rule Trojan_BAT_LummaStealer_SN_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 7b 03 00 00 04 06 06 9e 02 7b 03 00 00 04 06 94 28 14 00 00 0a 06 17 58 0a 06 02 7b 03 00 00 04 8e 69 32 db } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}