
rule Backdoor_BAT_RevengeRat_YAY_MTB{
	meta:
		description = "Backdoor:BAT/RevengeRat.YAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 06 09 6f ?? ?? ?? 0a 00 06 18 6f ?? ?? ?? 0a 00 06 6f ?? ?? ?? 0a 02 16 02 8e b7 6f ?? ?? ?? 0a 13 04 11 04 0b 2b 00 07 2a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}