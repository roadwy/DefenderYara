
rule TrojanSpy_BAT_Stealer_SP_MTB{
	meta:
		description = "TrojanSpy:BAT/Stealer.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 03 06 7e 04 00 00 04 06 91 04 06 04 8e 69 5d 91 61 d2 9c 00 06 17 58 0a 06 7e 04 00 00 04 8e 69 fe 04 0b 07 2d d9 } //2
		$a_81_1 = {53 68 72 6f 75 64 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 Shroud.Properties.Resources.resources
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}