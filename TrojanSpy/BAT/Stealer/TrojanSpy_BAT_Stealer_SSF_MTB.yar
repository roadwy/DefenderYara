
rule TrojanSpy_BAT_Stealer_SSF_MTB{
	meta:
		description = "TrojanSpy:BAT/Stealer.SSF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {28 2c 00 00 0a 73 2d 00 00 0a 20 f4 01 00 00 28 ?? ?? ?? 06 25 26 28 2e 00 00 0a 25 26 6f 2f 00 00 0a 25 26 0a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}