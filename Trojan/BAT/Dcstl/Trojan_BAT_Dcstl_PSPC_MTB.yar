
rule Trojan_BAT_Dcstl_PSPC_MTB{
	meta:
		description = "Trojan:BAT/Dcstl.PSPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 28 7d 00 00 0a 02 6f 90 01 03 0a 0a 28 90 01 03 0a 03 6f 90 01 03 0a 0b 06 73 90 01 03 0a 0c 08 07 6f 90 01 03 0a 28 90 01 03 06 0d 2b 00 09 2a 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}