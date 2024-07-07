
rule Trojan_BAT_CyberGate_KPAA_MTB{
	meta:
		description = "Trojan:BAT/CyberGate.KPAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 15 31 0c 07 28 90 01 01 00 00 2b 28 90 01 01 00 00 2b 0b 28 90 01 02 00 0a 07 6f 90 01 02 00 0a 0d 07 2c 26 90 00 } //4
		$a_01_1 = {52 65 76 65 72 73 65 } //1 Reverse
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}