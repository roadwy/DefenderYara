
rule Trojan_BAT_Blocker_SPQC_MTB{
	meta:
		description = "Trojan:BAT/Blocker.SPQC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 08 00 00 0a 72 90 01 03 70 28 90 01 03 0a 0d 09 28 90 01 03 2b 28 90 01 03 2b 0d dd 06 00 00 00 26 dd 00 00 00 00 09 2c d5 90 00 } //6
	condition:
		((#a_03_0  & 1)*6) >=6
 
}