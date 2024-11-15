
rule Backdoor_BAT_Havoc_KAB_MTB{
	meta:
		description = "Backdoor:BAT/Havoc.KAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {7e 04 00 00 0a 7e 01 00 00 04 8e 69 28 05 00 00 0a 20 00 10 00 00 1f 40 28 01 00 00 06 0a 7e 01 00 00 04 16 06 7e 01 00 00 04 8e 69 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}