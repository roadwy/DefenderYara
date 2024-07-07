
rule TrojanSpy_BAT_HiveMon_AHV_MTB{
	meta:
		description = "TrojanSpy:BAT/HiveMon.AHV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {a2 25 17 11 0b a2 25 18 16 8c 90 01 01 00 00 01 a2 6f 90 01 03 0a 26 00 de 0d 11 0a 2c 08 11 0a 6f 90 01 03 0a 00 dc 2a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}