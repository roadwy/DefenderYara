
rule TrojanSpy_BAT_Bobik_ABK_MTB{
	meta:
		description = "TrojanSpy:BAT/Bobik.ABK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 13 04 00 11 04 72 ?? 00 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 00 de 0d 11 04 2c 08 11 04 } //1
		$a_03_1 = {0a 12 00 28 ?? 00 00 0a 12 00 28 ?? 00 00 0a 73 2c 00 00 0a 0b 07 28 ?? 00 00 0a 0c 00 08 7e 2e 00 00 0a 7e 2e 00 00 0a 12 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}