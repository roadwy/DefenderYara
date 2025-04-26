
rule Trojan_BAT_Evilnum_SWB_MTB{
	meta:
		description = "Trojan:BAT/Evilnum.SWB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 09 08 6f 20 00 00 0a 6f 21 00 00 0a 26 11 04 6f 22 00 00 0a 09 6f 23 00 00 0a 00 09 16 09 6f 24 00 00 0a 6f 25 00 00 0a 26 00 17 13 05 2b d0 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}