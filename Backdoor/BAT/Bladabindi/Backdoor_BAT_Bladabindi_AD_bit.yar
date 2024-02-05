
rule Backdoor_BAT_Bladabindi_AD_bit{
	meta:
		description = "Backdoor:BAT/Bladabindi.AD!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {17 da 91 1f 70 61 90 09 04 00 03 03 8e 90 00 } //01 00 
		$a_01_1 = {07 11 05 03 11 05 91 06 61 09 08 91 61 } //01 00 
		$a_01_2 = {58 4f 52 5f 44 45 43 00 50 31 00 4b 31 } //00 00 
	condition:
		any of ($a_*)
 
}