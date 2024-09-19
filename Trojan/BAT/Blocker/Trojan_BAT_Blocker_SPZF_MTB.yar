
rule Trojan_BAT_Blocker_SPZF_MTB{
	meta:
		description = "Trojan:BAT/Blocker.SPZF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 16 11 19 11 09 91 13 28 11 19 11 09 11 28 11 20 61 19 11 18 58 61 11 32 61 d2 9c } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}