
rule TrojanSpy_BAT_Growtopia_ARW_MTB{
	meta:
		description = "TrojanSpy:BAT/Growtopia.ARW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 a2 25 18 72 ?? 03 00 70 a2 25 19 72 ?? 03 00 70 a2 25 1a 72 ?? 03 00 70 a2 25 1b 72 ?? 03 00 70 a2 25 1c 0e 06 a2 25 1d 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}