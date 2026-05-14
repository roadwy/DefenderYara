
rule Trojan_BAT_Heracles_SXB_MTB{
	meta:
		description = "Trojan:BAT/Heracles.SXB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 11 06 6f ?? 00 00 0a 13 07 07 11 07 16 11 07 8e 69 6f ?? 00 00 0a de 03 } //20
		$a_03_1 = {70 20 fa ff 00 00 6f ?? 00 00 0a 06 6f ?? 00 00 0a 75 ?? 00 00 01 0b 07 2c 08 07 6f ?? 00 00 0a 2d 07 72 ?? ?? 00 70 2b 0b 07 6f ?? 00 00 0a 6f ?? 00 00 0a 0c de 13 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}