
rule Trojan_BAT_DarkTortilla_MBXK_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.MBXK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 00 63 00 75 00 5e 00 64 00 6d 00 73 00 6a 00 5b 00 66 00 00 15 75 00 71 00 2f 00 2a 00 29 00 74 00 28 00 6f 00 23 00 65 00 00 15 23 00 21 00 6b 00 6d 00 70 00 63 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}