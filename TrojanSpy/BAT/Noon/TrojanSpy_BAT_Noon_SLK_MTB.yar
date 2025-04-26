
rule TrojanSpy_BAT_Noon_SLK_MTB{
	meta:
		description = "TrojanSpy:BAT/Noon.SLK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 08 6f 4b 00 00 0a 26 04 07 08 91 6f 4c 00 00 0a 08 17 58 0c 08 03 32 e7 } //2
		$a_81_1 = {53 61 6b 6b 20 41 6c 6b 61 6c 6d 61 7a } //2 Sakk Alkalmaz
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}