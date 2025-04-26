
rule TrojanSpy_BAT_Noon_SJK_MTB{
	meta:
		description = "TrojanSpy:BAT/Noon.SJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 06 91 04 28 16 00 00 06 06 17 58 0a 06 03 32 ef } //2
		$a_01_1 = {54 65 6d 70 65 72 61 74 75 72 65 43 6f 6e 76 65 72 74 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 TemperatureConverter.Properties.Resources.resources
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}