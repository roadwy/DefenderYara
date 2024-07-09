
rule Trojan_BAT_Dcstl_PTCN_MTB{
	meta:
		description = "Trojan:BAT/Dcstl.PTCN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 07 9a 0c 00 08 28 ?? 00 00 0a 0d 02 04 09 28 ?? 00 00 0a 6f 1f 00 00 0a 13 04 11 04 6f 20 00 00 0a 13 05 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}