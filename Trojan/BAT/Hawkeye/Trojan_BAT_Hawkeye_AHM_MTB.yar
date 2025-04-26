
rule Trojan_BAT_Hawkeye_AHM_MTB{
	meta:
		description = "Trojan:BAT/Hawkeye.AHM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 2d 02 2b 39 02 09 02 8e b7 5d 91 07 09 07 8e b7 5d 91 61 18 2d 40 26 02 09 02 8e b7 5d 08 02 09 17 d6 02 8e b7 5d 91 da 20 00 01 00 00 d6 20 00 01 00 00 5d b4 9c 09 15 d6 16 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}