
rule Trojan_BAT_Dcstl_PTBZ_MTB{
	meta:
		description = "Trojan:BAT/Dcstl.PTBZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 72 fd 03 00 70 28 ?? 00 00 0a 6f 17 00 00 0a 0a 72 48 05 00 70 0b 72 52 05 00 70 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}