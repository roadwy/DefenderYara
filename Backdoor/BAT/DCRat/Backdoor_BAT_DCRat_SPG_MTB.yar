
rule Backdoor_BAT_DCRat_SPG_MTB{
	meta:
		description = "Backdoor:BAT/DCRat.SPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 6f 08 00 00 0a 0b 07 72 53 00 00 70 6f ?? ?? ?? 0a a5 0a 00 00 01 13 04 12 04 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0c 08 28 ?? ?? ?? 06 26 09 6f 0c 00 00 0a 2d cb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}