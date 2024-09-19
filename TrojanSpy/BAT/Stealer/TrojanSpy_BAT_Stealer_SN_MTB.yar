
rule TrojanSpy_BAT_Stealer_SN_MTB{
	meta:
		description = "TrojanSpy:BAT/Stealer.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 7b 38 00 00 04 06 07 03 6f 40 00 00 0a 0c 08 2c 0f 07 08 58 0b 03 08 59 fe 0b 01 00 03 16 30 df } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}