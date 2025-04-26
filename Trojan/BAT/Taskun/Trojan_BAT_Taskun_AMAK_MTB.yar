
rule Trojan_BAT_Taskun_AMAK_MTB{
	meta:
		description = "Trojan:BAT/Taskun.AMAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {1f 16 5d 91 13 ?? 07 09 91 11 ?? 61 13 ?? 09 1b 58 1a 59 08 5d 18 58 18 59 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}