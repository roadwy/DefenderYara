
rule Trojan_BAT_LummaStealer_SQ_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.SQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 1d 5d 1f 0d d8 13 04 11 04 1f 32 fe 02 13 05 11 05 2c 05 17 0b 00 2b 04 00 16 0b 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}