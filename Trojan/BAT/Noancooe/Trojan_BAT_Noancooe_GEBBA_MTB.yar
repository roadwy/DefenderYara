
rule Trojan_BAT_Noancooe_GEBBA_MTB{
	meta:
		description = "Trojan:BAT/Noancooe.GEBBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b 26 16 0b 07 45 05 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0a 00 00 00 0a 00 00 00 d0 02 00 00 06 26 19 0b 2b dc } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}