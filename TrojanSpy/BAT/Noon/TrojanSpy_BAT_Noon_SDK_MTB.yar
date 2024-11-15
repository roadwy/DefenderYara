
rule TrojanSpy_BAT_Noon_SDK_MTB{
	meta:
		description = "TrojanSpy:BAT/Noon.SDK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 07 11 0a 95 11 07 11 09 95 58 20 ff 00 00 00 5f 13 10 11 06 11 08 11 04 11 08 91 11 07 11 10 95 61 28 48 00 00 0a 9c 11 08 17 58 13 08 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}