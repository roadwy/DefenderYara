
rule Trojan_BAT_DarkTortilla_DPV_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.DPV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 20 ff 00 00 00 5f b4 0a 2b 00 06 2a } //4
		$a_03_1 = {0a 2b 3f 00 02 6f ?? 02 00 0a 7e b6 02 00 04 2c 07 7e b6 02 00 04 2b 16 7e b1 02 00 04 fe 06 02 04 00 06 73 8f 02 00 0a 25 80 b6 02 00 04 28 ?? 00 00 2b 0b 28 ?? 02 00 0a 07 6f ?? 02 00 0a 0a 2b 00 06 2a } //5
	condition:
		((#a_01_0  & 1)*4+(#a_03_1  & 1)*5) >=9
 
}