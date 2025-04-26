
rule TrojanSpy_BAT_Noon_SJ_MTB{
	meta:
		description = "TrojanSpy:BAT/Noon.SJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 09 11 07 09 8e 69 5d 91 13 08 07 11 07 91 11 08 61 13 09 11 07 17 58 08 5d 13 0a 07 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}