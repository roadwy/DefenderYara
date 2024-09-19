
rule Backdoor_BAT_XWorm_GNK_MTB{
	meta:
		description = "Backdoor:BAT/XWorm.GNK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 02 1b 63 61 11 02 58 11 03 11 00 11 03 19 5f 94 58 61 59 13 01 20 0e 00 00 00 } //5
		$a_03_1 = {11 01 11 06 1f 10 63 d2 6f ?? ?? ?? 0a 20 07 00 00 00 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}