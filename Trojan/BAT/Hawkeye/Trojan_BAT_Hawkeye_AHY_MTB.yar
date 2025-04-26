
rule Trojan_BAT_Hawkeye_AHY_MTB{
	meta:
		description = "Trojan:BAT/Hawkeye.AHY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 0a 2b 2b 16 0b 2b 13 02 06 02 06 91 7e 01 00 00 04 07 91 61 d2 9c 07 17 58 0b 07 7e 01 00 00 04 8e 69 fe 04 13 04 11 04 2d dd } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}