
rule Backdoor_BAT_Bladabindi_MSD_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.MSD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {16 9a 0b 02 07 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2a 90 09 16 00 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0a 06 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}