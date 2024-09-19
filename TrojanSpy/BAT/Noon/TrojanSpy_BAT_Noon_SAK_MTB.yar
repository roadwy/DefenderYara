
rule TrojanSpy_BAT_Noon_SAK_MTB{
	meta:
		description = "TrojanSpy:BAT/Noon.SAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {04 05 5d 05 58 05 5d 0a 03 06 91 0b 07 0e 04 61 0c 08 0e 05 59 20 00 02 00 00 58 0d 2b 00 09 2a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}