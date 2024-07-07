
rule Trojan_BAT_Chopper_ACR_MTB{
	meta:
		description = "Trojan:BAT/Chopper.ACR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {25 16 03 a2 25 17 04 a2 25 18 06 a2 26 08 07 02 6f 12 00 00 0a 28 18 00 00 0a 74 1a 00 00 01 7b 19 00 00 0a 25 16 03 a2 25 17 04 a2 25 } //2
		$a_01_1 = {25 16 9a 74 12 00 00 01 fe 0b 01 00 25 17 9a 74 13 00 00 01 fe 0b 02 00 25 18 9a 0a 26 02 6f 12 00 00 0a 28 18 00 00 0a 74 1a 00 00 01 7b 19 00 00 0a 25 16 03 a2 25 17 04 a2 25 18 06 a2 26 02 } //2
		$a_01_2 = {5f 5f 52 65 6e 64 65 72 5f 5f 63 6f 6e 74 72 6f 6c 31 } //1 __Render__control1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}