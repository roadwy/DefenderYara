
rule Backdoor_BAT_nJRat_FVJ_MTB{
	meta:
		description = "Backdoor:BAT/nJRat.FVJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 08 06 08 1e 5a 1e 6f 90 01 03 0a 18 28 90 01 03 0a 9c 00 08 17 58 0c 08 07 8e 69 17 59 fe 02 16 fe 01 13 05 11 05 2d d6 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}