
rule Backdoor_BAT_Bladabindi_AAVT_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.AAVT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 13 05 16 13 04 2b 29 11 05 11 04 9a 0d 08 72 ?? ?? 00 70 09 28 ?? 01 00 0a 28 ?? 01 00 0a 28 ?? 01 00 0a 6f ?? 01 00 0a 26 11 04 17 d6 13 04 00 11 04 11 05 8e b7 fe 04 13 06 11 06 2d c9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}