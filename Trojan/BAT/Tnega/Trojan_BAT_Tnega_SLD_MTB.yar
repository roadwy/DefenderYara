
rule Trojan_BAT_Tnega_SLD_MTB{
	meta:
		description = "Trojan:BAT/Tnega.SLD!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 72 ff 06 00 70 6f 95 00 00 0a 75 2b 00 00 01 0b 73 00 01 00 0a 0c 20 00 0e 01 00 0d 07 08 09 28 46 00 00 06 00 d0 46 00 00 01 28 50 00 00 0a 06 72 09 07 00 70 6f 01 01 00 0a 20 00 01 00 00 14 14 17 8d 08 00 00 01 25 16 08 6f 02 01 00 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}