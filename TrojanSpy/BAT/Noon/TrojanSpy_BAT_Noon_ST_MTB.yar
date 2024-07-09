
rule TrojanSpy_BAT_Noon_ST_MTB{
	meta:
		description = "TrojanSpy:BAT/Noon.ST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 08 06 08 91 20 a7 20 3a 3a 28 27 00 00 06 28 ?? ?? ?? 0a 59 d2 9c 08 17 58 0c 08 06 8e 69 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}