
rule TrojanSpy_BAT_Noon_SB_MTB{
	meta:
		description = "TrojanSpy:BAT/Noon.SB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 0b 11 0c 91 07 11 07 17 58 11 06 5d 91 13 0d 08 11 07 08 6f 65 00 00 0a 5d 6f 66 00 00 0a 13 0e 11 0e 61 11 0d 59 20 00 01 00 00 58 20 ff 00 00 00 5f 13 0f 07 11 07 11 0f d2 9c 11 07 17 58 13 07 11 0c 17 58 13 0c 11 0c 11 0b 8e 69 32 b0 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}