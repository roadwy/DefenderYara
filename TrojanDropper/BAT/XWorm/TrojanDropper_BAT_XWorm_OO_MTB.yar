
rule TrojanDropper_BAT_XWorm_OO_MTB{
	meta:
		description = "TrojanDropper:BAT/XWorm.OO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 02 28 25 00 00 0a 7e 09 00 00 04 15 16 28 26 00 00 0a 16 9a 28 17 00 00 06 28 ?? ?? ?? 0a de 0f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}