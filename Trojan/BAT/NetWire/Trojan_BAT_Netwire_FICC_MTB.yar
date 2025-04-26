
rule Trojan_BAT_Netwire_FICC_MTB{
	meta:
		description = "Trojan:BAT/Netwire.FICC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 11 0b 8f 10 00 00 01 25 71 10 00 00 01 7e 01 00 00 04 11 0b 1f 10 5d 91 61 d2 81 10 00 00 01 00 11 0b 17 58 13 0b 11 0b 07 8e 69 fe 04 13 0e 11 0e 2d cb } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}