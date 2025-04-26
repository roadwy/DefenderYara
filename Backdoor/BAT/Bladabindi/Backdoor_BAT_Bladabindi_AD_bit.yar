
rule Backdoor_BAT_Bladabindi_AD_bit{
	meta:
		description = "Backdoor:BAT/Bladabindi.AD!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {17 da 91 1f 70 61 90 09 04 00 03 03 8e } //1
		$a_01_1 = {07 11 05 03 11 05 91 06 61 09 08 91 61 } //1
		$a_01_2 = {58 4f 52 5f 44 45 43 00 50 31 00 4b 31 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}