
rule Backdoor_BAT_Nabonot_MTB{
	meta:
		description = "Backdoor:BAT/Nabonot!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {28 26 00 00 06 28 ?? 00 00 06 28 ?? 00 00 0a 13 ?? 11 ?? 20 ?? ?? ?? ?? 5a 20 ?? ?? ?? ?? 61 38 ?? ?? ff ff } //1
		$a_02_1 = {20 c4 8e fb 0e 13 ?? 11 ?? 72 ?? 00 00 70 6f ?? 00 00 0a 13 ?? 11 ?? 20 ?? ?? ?? ?? fe 02 13 ?? 20 ?? ?? ?? ?? 38 ?? ?? ff ff } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}