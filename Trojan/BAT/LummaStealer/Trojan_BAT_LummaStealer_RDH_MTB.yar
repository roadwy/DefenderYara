
rule Trojan_BAT_LummaStealer_RDH_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.RDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0b 73 20 00 00 0a 0c 08 06 07 6f 21 00 00 0a 0d 73 22 00 00 0a 13 04 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}