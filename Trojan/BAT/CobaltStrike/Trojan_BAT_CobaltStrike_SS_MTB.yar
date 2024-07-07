
rule Trojan_BAT_CobaltStrike_SS_MTB{
	meta:
		description = "Trojan:BAT/CobaltStrike.SS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {71 a8 9a b2 71 a8 e2 b2 71 a8 da b2 71 88 aa b2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}