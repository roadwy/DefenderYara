
rule Trojan_BAT_LummaStealer_NB_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 05 25 4b 11 0c 11 0f 1f 0f 5f 95 61 54 } //5
		$a_81_1 = {66 63 34 33 61 32 39 36 2d 39 65 61 30 2d 34 39 30 63 2d 39 30 65 61 2d 34 62 64 32 31 65 32 34 31 38 36 32 } //5 fc43a296-9ea0-490c-90ea-4bd21e241862
	condition:
		((#a_01_0  & 1)*5+(#a_81_1  & 1)*5) >=10
 
}