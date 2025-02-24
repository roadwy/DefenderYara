
rule TrojanSpy_BAT_Noon_SIK_MTB{
	meta:
		description = "TrojanSpy:BAT/Noon.SIK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 06 07 1f 10 5d 04 07 5a 68 9d 02 03 04 07 05 28 44 00 00 06 00 00 07 17 58 0b 07 02 6f b5 00 00 0a 2f 0b 03 6f b1 00 00 0a 05 fe 04 2b 01 16 0c 08 2d cc } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}