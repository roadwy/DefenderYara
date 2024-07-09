
rule Backdoor_BAT_Bladabindi_BG{
	meta:
		description = "Backdoor:BAT/Bladabindi.BG,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {38 00 34 00 ?? ?? 38 00 36 00 ?? ?? 31 00 31 00 33 00 ?? ?? 38 00 31 00 ?? ?? 36 00 35 00 } //1
		$a_03_1 = {36 00 35 00 ?? ?? 36 00 39 00 ?? ?? 38 00 35 00 ?? ?? 36 00 35 00 ?? ?? 38 00 34 00 ?? ?? 31 00 30 00 33 00 ?? ?? 36 00 36 00 ?? ?? 38 00 35 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}