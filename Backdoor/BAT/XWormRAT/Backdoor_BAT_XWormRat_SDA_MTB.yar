
rule Backdoor_BAT_XWormRat_SDA_MTB{
	meta:
		description = "Backdoor:BAT/XWormRat.SDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 07 72 11 00 00 70 28 ?? ?? ?? 0a 13 08 } //1
		$a_03_1 = {28 0d 00 00 0a 2c 08 11 08 28 ?? ?? ?? 0a 00 11 08 28 ?? ?? ?? 0a 2d 0d 11 08 28 0e 00 00 06 28 0f 00 00 0a } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}