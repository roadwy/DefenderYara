
rule TrojanSpy_BAT_Noon_SHK_MTB{
	meta:
		description = "TrojanSpy:BAT/Noon.SHK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 11 04 11 0a 11 04 11 0a 91 20 9d 07 00 00 59 d2 9c 00 11 0a 17 58 13 0a 11 0a 11 04 8e 69 fe 04 13 0b 11 0b 2d d9 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}