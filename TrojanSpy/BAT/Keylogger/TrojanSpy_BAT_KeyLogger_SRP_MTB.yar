
rule TrojanSpy_BAT_KeyLogger_SRP_MTB{
	meta:
		description = "TrojanSpy:BAT/KeyLogger.SRP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 03 04 05 0e 04 0e 05 0e 06 28 ?? ?? ?? 06 2d 06 06 17 58 0a 2b 04 15 0b de 0c 06 1f 0a 31 e0 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}