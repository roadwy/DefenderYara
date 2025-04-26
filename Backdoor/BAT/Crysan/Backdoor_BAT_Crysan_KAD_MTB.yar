
rule Backdoor_BAT_Crysan_KAD_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.KAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {17 64 61 fe 0e 2f 00 fe 0c 2f 00 fe 0c 27 00 58 fe 0e 2f 00 fe 0c 17 00 1e 62 fe 0c 13 00 58 fe 0c 17 00 61 fe 0c 2f 00 58 fe 0e 2f 00 fe 0c 2f 00 76 6c 6d 58 13 2e } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}