
rule Trojan_BAT_Blocker_SM_MTB{
	meta:
		description = "Trojan:BAT/Blocker.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 09 18 6f 88 01 00 0a 1f 10 28 1b 03 00 0a 13 04 11 04 16 32 08 08 11 04 6f 1c 03 00 0a 09 18 58 0d 09 07 6f 08 01 00 0a 32 d5 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}