
rule Trojan_BAT_Xmrig_PSBQ_MTB{
	meta:
		description = "Trojan:BAT/Xmrig.PSBQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 7f 00 00 0a 28 59 00 00 0a 7e 24 00 00 04 6f 80 00 00 0a 6f 81 00 00 0a 0a } //5
		$a_01_1 = {00 8d 44 00 00 01 0b 28 56 00 00 06 0c 7e 18 00 00 04 06 07 28 0e 00 00 06 28 46 00 00 06 28 01 00 00 0a 3a 84 02 00 00 7e 30 00 00 04 28 69 00 00 0a 3a 0f 00 00 00 7e 06 00 00 04 7e 30 00 00 04 28 34 00 00 06 7e 30 00 00 04 73 64 00 00 0a 28 a5 00 00 0a } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}