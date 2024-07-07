
rule Trojan_BAT_SideWinder_A_MTB{
	meta:
		description = "Trojan:BAT/SideWinder.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {02 8e 69 1f 20 59 8d 90 01 04 0a 02 1f 20 06 16 06 8e 69 28 90 01 04 16 0b 2b 16 06 07 8f 90 1b 00 25 47 02 07 1f 20 5d 91 61 d2 52 07 17 58 0b 07 06 8e 69 32 e4 06 2a 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}