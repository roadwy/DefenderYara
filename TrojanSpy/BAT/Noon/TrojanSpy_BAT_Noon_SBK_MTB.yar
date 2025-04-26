
rule TrojanSpy_BAT_Noon_SBK_MTB{
	meta:
		description = "TrojanSpy:BAT/Noon.SBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 05 08 5d 08 58 08 5d 13 09 07 11 09 91 11 06 61 11 08 59 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}