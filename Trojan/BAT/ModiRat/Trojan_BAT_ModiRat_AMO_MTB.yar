
rule Trojan_BAT_ModiRat_AMO_MTB{
	meta:
		description = "Trojan:BAT/ModiRat.AMO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0b 16 0c 08 28 ?? 00 00 06 20 01 80 ff ff fe 01 0d 09 2c 54 08 13 04 02 11 04 28 ?? 00 00 06 13 05 11 05 6f ?? 00 00 0a 16 fe 02 13 06 11 06 2c 2d 02 } //2
		$a_01_1 = {6d 00 79 00 68 00 6f 00 75 00 73 00 65 00 63 00 61 00 6d 00 2e 00 64 00 64 00 6e 00 73 00 2e 00 6e 00 65 00 74 00 } //3 myhousecam.ddns.net
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*3) >=5
 
}